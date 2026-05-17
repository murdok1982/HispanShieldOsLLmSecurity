//! aegis-pqc — Post-quantum cryptography for HispanShield inter-daemon channels
//!
//! Implements a hybrid KEM (X25519 + Kyber768) and hybrid signing (Dilithium3)
//! so that the channel is secure against both classical and quantum adversaries
//! simultaneously — harvest-now/decrypt-later mitigation.
//!
//! Standards:
//!   - NIST FIPS 203 (ML-KEM, formerly Kyber)
//!   - NIST FIPS 204 (ML-DSA, formerly Dilithium)
//!   - HKDF-SHA3-256 for key derivation (NIST SP 800-56C Rev2)
//!   - AES-256-GCM for symmetric encryption

use hkdf::Hkdf;
use pqcrypto_dilithium::dilithium3::{
    self, DetachedSignature, PublicKey as DilithiumPub, SecretKey as DilithiumSec,
};
use pqcrypto_kyber::kyber768::{self, Ciphertext, PublicKey as KyberPub, SecretKey as KyberSec};
use pqcrypto_traits::{
    kem::{Ciphertext as _, PublicKey as _, SharedSecret as _},
    sign::{DetachedSignature as _, PublicKey as _},
};
use rand::RngCore;
use sha3::Sha3_256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Pub, X25519_BASEPOINT_BYTES};

pub use aes_gcm::aead::OsRng;

// ── Error type ─────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum PqcError {
    #[error("Signature verification failed")]
    SignatureVerification,
    #[error("AEAD decryption failed: {0}")]
    AeadDecrypt(String),
    #[error("Key material size mismatch")]
    KeySize,
    #[error("Invalid peer public key")]
    InvalidPeerKey,
}

// ── Hybrid KEM ─────────────────────────────────────────────────────────────────

/// Public key bundle for the hybrid KEM (X25519 + Kyber768).
/// Sent by the receiver to the sender at session establishment.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct HybridKemPublicKey {
    /// Kyber768 public key bytes (FIPS 203 ML-KEM-768)
    pub kyber_pk: Vec<u8>,
    /// X25519 long-term public key bytes (32 bytes)
    pub x25519_pk: [u8; 32],
}

/// Long-lived key pair for receiving hybrid KEM encapsulations.
/// The X25519 secret is stored as raw bytes; in x25519-dalek v2 the
/// `StaticSecret` type was removed — the raw `x25519()` function is used instead.
pub struct HybridKemKeyPair {
    kyber_pk: KyberPub,
    kyber_sk: KyberSec,
    /// Raw 32-byte X25519 scalar (clamped by the x25519() function at use time).
    x25519_sk_bytes: [u8; 32],
    x25519_pk_bytes: [u8; 32],
}

impl HybridKemKeyPair {
    pub fn generate() -> Self {
        let (kyber_pk, kyber_sk) = kyber768::keypair();

        let mut x25519_sk_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut x25519_sk_bytes);
        // Derive public key: scalar multiplication of secret × basepoint
        let x25519_pk_bytes = x25519_dalek::x25519(x25519_sk_bytes, X25519_BASEPOINT_BYTES);

        Self { kyber_pk, kyber_sk, x25519_sk_bytes, x25519_pk_bytes }
    }

    pub fn public_key(&self) -> HybridKemPublicKey {
        HybridKemPublicKey {
            kyber_pk: self.kyber_pk.as_bytes().to_vec(),
            x25519_pk: self.x25519_pk_bytes,
        }
    }
}

/// Result of a successful KEM encapsulation — sent to the receiver.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct HybridEncapsulation {
    /// Kyber768 ciphertext
    pub kyber_ct: Vec<u8>,
    /// Ephemeral X25519 public key
    pub x25519_eph_pk: [u8; 32],
}

/// Encapsulate a shared secret to a remote public key bundle.
/// Returns the encapsulation (to send) and the derived symmetric key (local use).
pub fn encapsulate(
    recipient_pk: &HybridKemPublicKey,
) -> Result<(HybridEncapsulation, [u8; 32]), PqcError> {
    // Reconstruct Kyber public key and encapsulate
    let kyber_pk = KyberPub::from_bytes(&recipient_pk.kyber_pk)
        .map_err(|_| PqcError::InvalidPeerKey)?;
    let (kyber_ss, kyber_ct) = kyber768::encapsulate(&kyber_pk);

    // Ephemeral X25519 DH: generate ephemeral key pair, compute shared secret
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = X25519Pub::from(&eph_secret);
    let peer_x25519 = X25519Pub::from(recipient_pk.x25519_pk);
    let x25519_ss = eph_secret.diffie_hellman(&peer_x25519);

    let shared_key = derive_hybrid_key(x25519_ss.as_bytes(), kyber_ss.as_bytes());

    Ok((
        HybridEncapsulation {
            kyber_ct: kyber_ct.as_bytes().to_vec(),
            x25519_eph_pk: *eph_pub.as_bytes(),
        },
        shared_key,
    ))
}

/// Decapsulate a shared secret from a received encapsulation.
pub fn decapsulate(
    key_pair: &HybridKemKeyPair,
    encap: &HybridEncapsulation,
) -> Result<[u8; 32], PqcError> {
    // Kyber768 decapsulation
    let kyber_ct = Ciphertext::from_bytes(&encap.kyber_ct)
        .map_err(|_| PqcError::InvalidPeerKey)?;
    let kyber_ss = kyber768::decapsulate(&kyber_ct, &key_pair.kyber_sk);

    // X25519 DH: x25519(my_secret_scalar, their_ephemeral_public)
    let x25519_ss_bytes =
        x25519_dalek::x25519(key_pair.x25519_sk_bytes, encap.x25519_eph_pk);

    Ok(derive_hybrid_key(&x25519_ss_bytes, kyber_ss.as_bytes()))
}

/// HKDF-SHA3-256 over the concatenation of classical and PQ shared secrets.
/// Both components must be compromised simultaneously to break security.
fn derive_hybrid_key(classical_ss: &[u8], pq_ss: &[u8]) -> [u8; 32] {
    let combined = [classical_ss, pq_ss].concat();
    let hk = Hkdf::<Sha3_256>::new(None, &combined);
    let mut okm = [0u8; 32];
    hk.expand(b"hispanshield-hybrid-kem-v1", &mut okm)
        .expect("HKDF expand with 32-byte output never fails");
    okm
}

// ── Hybrid signing (Dilithium3 — NIST FIPS 204) ────────────────────────────────

/// Signing key pair: Dilithium3 for the PQ layer.
pub struct SigningKeyPair {
    pub public: DilithiumPub,
    secret: DilithiumSec,
}

impl SigningKeyPair {
    pub fn generate() -> Self {
        let (public, secret) = dilithium3::keypair();
        Self { public, secret }
    }

    /// Sign a message with Dilithium3.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        dilithium3::detached_sign(message, &self.secret)
            .as_bytes()
            .to_vec()
    }

    /// Export the public key bytes for distribution to peers.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public.as_bytes().to_vec()
    }
}

/// Verify a Dilithium3 detached signature.
pub fn verify_signature(
    message: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<(), PqcError> {
    let pk = DilithiumPub::from_bytes(public_key_bytes)
        .map_err(|_| PqcError::InvalidPeerKey)?;
    let sig = DetachedSignature::from_bytes(signature_bytes)
        .map_err(|_| PqcError::SignatureVerification)?;
    // pqcrypto-dilithium 0.5 uses verify_detached_signature (with full suffix)
    dilithium3::verify_detached_signature(&sig, message, &pk)
        .map_err(|_| PqcError::SignatureVerification)
}

// ── Authenticated encryption on established channel ────────────────────────────

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};

/// Encrypt a plaintext with AES-256-GCM using the derived hybrid key.
/// Returns (nonce || ciphertext) suitable for transmission.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("AES-GCM encrypt");
    [nonce_bytes.as_slice(), ciphertext.as_slice()].concat()
}

/// Decrypt a (nonce || ciphertext) blob produced by `encrypt`.
pub fn decrypt(key: &[u8; 32], nonce_and_ct: &[u8]) -> Result<Vec<u8>, PqcError> {
    if nonce_and_ct.len() < 12 {
        return Err(PqcError::KeySize);
    }
    let (nonce_bytes, ct) = nonce_and_ct.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|e| PqcError::AeadDecrypt(e.to_string()))
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_kem_roundtrip() {
        let receiver = HybridKemKeyPair::generate();
        let pk = receiver.public_key();
        let (encap, sender_key) = encapsulate(&pk).unwrap();
        let receiver_key = decapsulate(&receiver, &encap).unwrap();
        assert_eq!(sender_key, receiver_key, "Shared secrets must match");
    }

    #[test]
    fn aead_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"HispanShield secret inter-daemon message";
        let blob = encrypt(&key, plaintext);
        let recovered = decrypt(&key, &blob).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn aead_tampered_ciphertext_rejected() {
        let key = [0x42u8; 32];
        let mut blob = encrypt(&key, b"sensitive");
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(decrypt(&key, &blob).is_err());
    }

    #[test]
    fn signing_roundtrip() {
        let kp = SigningKeyPair::generate();
        let msg = b"HispanShield attestation payload";
        let sig = kp.sign(msg);
        assert!(verify_signature(msg, &sig, &kp.public_key_bytes()).is_ok());
    }

    #[test]
    fn signing_wrong_message_rejected() {
        let kp = SigningKeyPair::generate();
        let sig = kp.sign(b"original");
        assert!(verify_signature(b"tampered", &sig, &kp.public_key_bytes()).is_err());
    }

    #[test]
    fn full_secure_channel() {
        let receiver_kem = HybridKemKeyPair::generate();
        let sender_signing = SigningKeyPair::generate();

        // Sender: encapsulate session key, sign plaintext, encrypt it
        let (encap, session_key) = encapsulate(&receiver_kem.public_key()).unwrap();
        let plaintext = b"CLASSIFIED: aegis-sentinel to aegis-gatekeeper";
        let signature = sender_signing.sign(plaintext);
        let ciphertext = encrypt(&session_key, plaintext);

        // Receiver: decapsulate session key, decrypt, verify signature
        let recovered_key = decapsulate(&receiver_kem, &encap).unwrap();
        let recovered_plain = decrypt(&recovered_key, &ciphertext).unwrap();
        assert!(verify_signature(
            &recovered_plain,
            &signature,
            &sender_signing.public_key_bytes()
        )
        .is_ok());
        assert_eq!(recovered_plain, plaintext);
    }
}
