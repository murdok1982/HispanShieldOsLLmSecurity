# HispanShield OS LLmSecurity

**HispanShield OS LLmSecurity** is a premium Linux-based operating system designed from the ground up with a **Zero-Trust** mindset, locally orchestrated by an autonomous artificial intelligence (native *LLM* models integrated directly into the system layer).

Designed with a fluid *macOS-inspired* aesthetic, this system replaces fragile traditional scripts and intensive human oversight with an intelligent, vigilant Agent residing deep within the operating system core.

---

## 🔒 Capabilities and "Zero-Trust" Principles

1. **Telemetry Isolation (*AegisEye*)**: The telemetry observer directly reads system metrics continuously at a ring-0 (kernel level) pacing. This eliminates state-poisoning by malicious execution payloads in user-space. The Agent truly "feels" the real pulse of the workstation.
2. **Local LLM Engine (*Qwen2.5-1.5B/Gemma2B*)**: Factory-integrated. Provides extremely rich generative AI capabilities with an outstanding minimal footprint (~1GB RAM footprint), coupled with utter network isolation (Air-gapped architecture) rendering external data exfiltration impossible.
3. **"No-Free-Shell" Doctrine**: HispanShield purposefully avoids the classic yet highly insecure "AI terminal access". The LLM never touches `bash` directly. Prompt-derived logic goes straight into a typed Router enforcing strictly schematized actions.
4. **Interactive Gatekeeper (Policy Engine)**: Absolute core or deep modifications are blocked by default. Legitimate minor tasks, like isolating a background PID, are mathematically authorized; sensitive core modifications force a disruptive popup inside the *Aegis Security Center* demanding a human override (UID 1000 fallback).

---

## 🖥 Premium Experience (UI)

The window into *HispanShield OS* runs on Tauri+React technology, resulting in a compiled, rapid native desktop interaction.
- **Desktop & Dock Layout**: Features silky smooth animations, an anchored bottom launch dock, and a seamless top status bar typical of mac environments.
- **Aegis Security Center**: An exquisite glassmorphism audit dashboard serving a live forensic log array tracing every single interaction and firewall blockage commanded by the AI Policy Engine.
- **Spotlight Agent Widget**: Always ready, conversational layout for Natural Language orders targeting low-level host logic.

---

## 💿 Installation Process

There are two primary methods to deploy.

### Method 1: Bare-Metal (Install via official .iso Image)
This represents the standalone route for fully transitioning hardware over to HispanShield OS.
1. Build or download the `HispanShieldOS-LLmSecurity-Release1.iso` file. *(Note: To manually build an ISO you will need a Debian/Ubuntu host environment and execute `build_iso.sh`).*
2. Leverage industry tools such as **Rufus** or **BalenaEtcher** to flash the `.iso` onto an 8GB+ reliable USB storage device.
3. Boot the designated PC confirming BIOS rules permit temporary drive execution.
4. The Installer applies Secure Sum Checks matching exact commercial hashes. Upon booting into the default configuration, it will safely download and SHA256-verify the GGUF LLM before activating the system loop.

### Method 2: Embedded Subsystem / Remote Headless Boot
Applicable if you are running an existing Linux setup (Debian 12):
1. Relocate this entire project tree under a primary directory like `~/hispanshieldos/`.
2. Elevate privileges and kick-start the core injection sequence:
   ```bash
   sudo ./installer/install.sh
   ```
3. The script automatically isolates environments, creating captive user privileges specifically for the LLM daemon while booting inter-process communication sockets. To achieve GUI operability you must then run npm setups inside the `ui/aegis-desktop` to launch the *Desktop UI*.
