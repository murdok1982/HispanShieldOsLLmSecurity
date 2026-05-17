#!/usr/bin/env python3
"""
HispanShield OS — Guardrails Integration Shim
==============================================
Wraps :class:`HispanShieldGuardrails` and exposes two synchronous-friendly
coroutines that the Sentinel orchestrator calls before and after every LLM
invocation:

    await apply_input_rails(message, context)   → GuardrailResult
    await apply_output_rails(response, context) → GuardrailResult

Every rail decision is HMAC-signed with the deployment key and written to the
audit channel so that downstream SIEM tooling can verify log integrity.

Environment variables
---------------------
HISPANSHIELD_GUARDRAILS_CONFIG  path to NeMo Guardrails config dir
                                (default: /opt/hispanshield/core/nemo-guardrails/config)
HISPANSHIELD_CLEARANCE_LEVEL    operator classification level
                                (default: UNCLASSIFIED)
HISPANSHIELD_AUDIT_KEY          hex-encoded 32-byte HMAC key
                                (default: deterministic dev key — CHANGE IN PRODUCTION)
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Path bootstrap — allow running from repo root without installation
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[3]
_NEMO_DIR  = _REPO_ROOT / "core" / "nemo-guardrails"

if str(_NEMO_DIR) not in sys.path:
    sys.path.insert(0, str(_NEMO_DIR))

from guardrails_engine import GuardrailResult, HispanShieldGuardrails  # noqa: E402

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_CONFIG_PATH = os.environ.get(
    "HISPANSHIELD_GUARDRAILS_CONFIG",
    "/opt/hispanshield/core/nemo-guardrails/config",
)
_CLEARANCE_LEVEL = os.environ.get("HISPANSHIELD_CLEARANCE_LEVEL", "UNCLASSIFIED")

# HMAC key: 32-byte dev default — operators MUST override via env var in prod.
_AUDIT_KEY_HEX = os.environ.get(
    "HISPANSHIELD_AUDIT_KEY",
    "a3f8c2d1e4b76091f25a8e3c7d4b9f0e1a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
)
try:
    _AUDIT_KEY = bytes.fromhex(_AUDIT_KEY_HEX)
except ValueError:
    _AUDIT_KEY = _AUDIT_KEY_HEX.encode()  # fallback: raw bytes

# ---------------------------------------------------------------------------
# Audit channel logger
# ---------------------------------------------------------------------------
_AUDIT_LOG_PATH = Path(
    os.environ.get(
        "HISPANSHIELD_GUARDRAILS_LOG",
        "/var/log/hispanshield/guardrails.log",
    )
)

logging.basicConfig(level=logging.WARNING)
_log = logging.getLogger("hispanshield.sentinel.guardrails_integration")


def _get_audit_logger() -> logging.Logger:
    logger = logging.getLogger("hispanshield.guardrails.audit_channel")
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        try:
            _AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(str(_AUDIT_LOG_PATH))
        except PermissionError:
            fh = logging.StreamHandler()
        fh.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(fh)
    return logger


_audit_logger = _get_audit_logger()


# ---------------------------------------------------------------------------
# HMAC helper
# ---------------------------------------------------------------------------
def _hmac_sign(payload: Dict[str, Any]) -> str:
    """Return a hex HMAC-SHA256 digest of the JSON-serialised *payload*."""
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    return hmac.new(_AUDIT_KEY, raw, hashlib.sha256).hexdigest()


def _write_hmac_audit(event: Dict[str, Any]) -> None:
    """Serialise *event* to the audit channel with an appended HMAC field."""
    event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    event["_hmac"] = _hmac_sign(event)
    _audit_logger.info(json.dumps(event, ensure_ascii=False))


# ---------------------------------------------------------------------------
# Singleton engine factory
# ---------------------------------------------------------------------------
_engine: Optional[HispanShieldGuardrails] = None


def _get_engine() -> HispanShieldGuardrails:
    global _engine
    if _engine is None:
        _engine = HispanShieldGuardrails(
            config_path=_CONFIG_PATH,
            classification_level=_CLEARANCE_LEVEL,
        )
    return _engine


def reset_engine(
    config_path: Optional[str] = None,
    classification_level: Optional[str] = None,
) -> None:
    """
    Force re-initialisation of the guardrails engine singleton.
    Useful in tests and when the operator changes the clearance level at
    runtime.
    """
    global _engine
    _engine = HispanShieldGuardrails(
        config_path=config_path or _CONFIG_PATH,
        classification_level=classification_level or _CLEARANCE_LEVEL,
    )


# ---------------------------------------------------------------------------
# Public coroutines called by the Sentinel orchestrator
# ---------------------------------------------------------------------------
async def apply_input_rails(
    message: str,
    context: Optional[Dict[str, Any]] = None,
) -> GuardrailResult:
    """
    Run all NeMo / regex input rails against *message*.

    Must be awaited before passing the user's message to the LLM.
    Writes an HMAC-signed audit record to the guardrails log.

    Parameters
    ----------
    message:
        Raw user-supplied text.
    context:
        Session context dictionary.  Expected keys:

        - ``clearance_level`` (str): user's classification clearance
        - ``requested_data_level`` (str): inferred classification of the request
        - ``session_id`` (str): unique session identifier

    Returns
    -------
    GuardrailResult
        ``allowed=False`` means the orchestrator MUST NOT send the message to
        the LLM and should return ``modified_response`` to the user instead.
    """
    ctx = context or {}
    t0 = time.monotonic()
    engine = _get_engine()

    try:
        result = await engine.check_input(message, ctx)
    except Exception as exc:
        _log.error("apply_input_rails error: %s", exc, exc_info=True)
        result = GuardrailResult(
            allowed=False,
            reason=f"guardrail_engine_error:{exc}",
            modified_response=(
                "Error interno en el sistema de seguridad. "
                "Solicitud bloqueada por precaución."
            ),
            audit_event={"event": "guardrail_engine_error", "error": str(exc)},
        )

    _write_hmac_audit({
        "component": "guardrails_integration",
        "rail": "input",
        "allowed": result.allowed,
        "reason": result.reason,
        "session_id": ctx.get("session_id", "unknown"),
        "clearance_level": ctx.get("clearance_level", _CLEARANCE_LEVEL),
        "latency_ms": round((time.monotonic() - t0) * 1000, 2),
        **result.audit_event,
    })
    return result


async def apply_output_rails(
    response: str,
    context: Optional[Dict[str, Any]] = None,
) -> GuardrailResult:
    """
    Run all NeMo / regex output rails against the LLM *response*.

    Must be awaited before returning the LLM's text to the user.
    Writes an HMAC-signed audit record to the guardrails log.

    Parameters
    ----------
    response:
        Raw text produced by the LLM.
    context:
        Same session context dictionary used for the corresponding input call.

    Returns
    -------
    GuardrailResult
        ``allowed=False`` means the orchestrator MUST replace the LLM output
        with ``modified_response`` before returning it to the client.
    """
    ctx = context or {}
    t0 = time.monotonic()
    engine = _get_engine()

    try:
        result = await engine.check_output(response, ctx)
    except Exception as exc:
        _log.error("apply_output_rails error: %s", exc, exc_info=True)
        result = GuardrailResult(
            allowed=False,
            reason=f"guardrail_engine_error:{exc}",
            modified_response=(
                "Error interno en el sistema de seguridad de salida. "
                "Respuesta bloqueada por precaución."
            ),
            audit_event={"event": "guardrail_engine_error", "error": str(exc)},
        )

    _write_hmac_audit({
        "component": "guardrails_integration",
        "rail": "output",
        "allowed": result.allowed,
        "reason": result.reason,
        "session_id": ctx.get("session_id", "unknown"),
        "latency_ms": round((time.monotonic() - t0) * 1000, 2),
        **result.audit_event,
    })
    return result


# ---------------------------------------------------------------------------
# Synchronous wrappers (convenience for callers that cannot use async/await)
# ---------------------------------------------------------------------------
def apply_input_rails_sync(
    message: str,
    context: Optional[Dict[str, Any]] = None,
) -> GuardrailResult:
    """Synchronous wrapper around :func:`apply_input_rails`."""
    return asyncio.get_event_loop().run_until_complete(
        apply_input_rails(message, context)
    )


def apply_output_rails_sync(
    response: str,
    context: Optional[Dict[str, Any]] = None,
) -> GuardrailResult:
    """Synchronous wrapper around :func:`apply_output_rails`."""
    return asyncio.get_event_loop().run_until_complete(
        apply_output_rails(response, context)
    )


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Guardrails Integration — quick self-test"
    )
    parser.add_argument(
        "--message",
        default="¿Cuál es el estado actual de las operaciones?",
        help="Input message to test",
    )
    parser.add_argument(
        "--clearance",
        default="SECRET",
        help="Simulated clearance level",
    )
    args = parser.parse_args()

    ctx: Dict[str, Any] = {
        "clearance_level": args.clearance,
        "requested_data_level": "UNCLASSIFIED",
        "session_id": "self-test-001",
    }

    async def _run() -> None:
        print("=== INPUT RAILS ===")
        r_in = await apply_input_rails(args.message, ctx)
        print(json.dumps(
            {"allowed": r_in.allowed, "reason": r_in.reason},
            indent=2, ensure_ascii=False,
        ))

        sample_response = "La situación operativa es nominal. No hay amenazas activas."
        print("\n=== OUTPUT RAILS ===")
        r_out = await apply_output_rails(sample_response, ctx)
        print(json.dumps(
            {"allowed": r_out.allowed, "reason": r_out.reason},
            indent=2, ensure_ascii=False,
        ))

    asyncio.run(_run())
