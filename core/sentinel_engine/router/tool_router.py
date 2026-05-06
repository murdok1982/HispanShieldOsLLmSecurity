"""
Sentinel Engine — Tool Router (REFERENCE / DEV HARNESS)
=======================================================

This Python implementation is NOT the production enforcement path. It exists
as a development harness for prompt-engineering and offline experimentation.
The authoritative gatekeeper is the Rust crate at
``core/rust/aegis-gatekeeper`` and ``core/rust/aegis-sentinel/src/tool_router.rs``;
the systemd unit ``aegis-agent-core.service`` only ever invokes the Rust path.

Both implementations consume the same allowlist file:

    core/policy/tools.yaml   (single source of truth — see header)

If you change ``tools.yaml`` you MUST also patch
``aegis-gatekeeper/src/lib.rs::PolicyEngine::new`` in the same PR. A future
sprint will add a ``cargo test`` that diffs the two and fails CI on drift.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [ToolRouter] - %(message)s")

# Resolve the canonical YAML relative to the repo root, regardless of CWD.
_POLICY_FILE = Path(__file__).resolve().parents[3] / "core" / "policy" / "tools.yaml"


def _load_allowlist(policy_path: Path = _POLICY_FILE) -> Dict[str, Dict[str, bool]]:
    """Parse the canonical YAML and flatten it into ``{tool: {requires_human, dual_mfa}}``.

    PyYAML is an optional dev-only dependency. If it is missing we fall back to
    a hardcoded mirror of the Rust list so unit tests can still run on minimal
    environments. The fallback is intentionally a strict subset; callers MUST
    rely on the Rust enforcer for production decisions.
    """
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError:
        logging.warning("PyYAML not installed — using inline mirror of the Rust allowlist.")
        return _RUST_MIRROR.copy()

    if not policy_path.is_file():
        logging.warning("Policy file %s missing — using inline mirror.", policy_path)
        return _RUST_MIRROR.copy()

    with policy_path.open("r", encoding="utf-8") as fh:
        document: Dict[str, Any] = yaml.safe_load(fh) or {}

    flat: Dict[str, Dict[str, bool]] = {}
    for category, tools in document.items():
        if category == "version" or not isinstance(tools, dict):
            continue
        for name, spec in tools.items():
            if not isinstance(spec, dict):
                continue
            flat[name] = {
                "requires_human": bool(spec.get("requires_human", True)),
                "dual_mfa": bool(spec.get("dual_mfa", False)),
            }
    return flat


# Inline mirror — last-resort fallback only. Keep in lockstep with the Rust
# PolicyEngine and tools.yaml. Anything not listed here is denied.
_RUST_MIRROR: Dict[str, Dict[str, bool]] = {
    "os_process_list":         {"requires_human": False, "dual_mfa": False},
    "os_ram_status":           {"requires_human": False, "dual_mfa": False},
    "file_read_safe_zone":     {"requires_human": False, "dual_mfa": False},
    "network_firewall_block":  {"requires_human": True,  "dual_mfa": False},
    "system_shutdown":         {"requires_human": True,  "dual_mfa": False},
    "nmap_scan":               {"requires_human": True,  "dual_mfa": False},
    "masscan_scan":            {"requires_human": True,  "dual_mfa": False},
    "nuclei_scan":             {"requires_human": True,  "dual_mfa": False},
    "openvas_scan":            {"requires_human": True,  "dual_mfa": False},
    "john_crack":              {"requires_human": True,  "dual_mfa": False},
    "hashcat_crack":           {"requires_human": True,  "dual_mfa": False},
    "owasp_zap_scan":          {"requires_human": True,  "dual_mfa": False},
    "sqlmap_scan":             {"requires_human": True,  "dual_mfa": False},
    "metasploit_exploit":      {"requires_human": True,  "dual_mfa": True},
    "honeypot_deploy":         {"requires_human": True,  "dual_mfa": True},
    "deception_setup":         {"requires_human": True,  "dual_mfa": True},
    "attribution_analysis":    {"requires_human": True,  "dual_mfa": True},
    "cyber_wargame":           {"requires_human": True,  "dual_mfa": True},
    "compliance_scan":         {"requires_human": True,  "dual_mfa": False},
}


class StrictToolRouter:
    """Dev/reference router. Production traffic is gated by the Rust crate."""

    def __init__(self, policy_engine_instance: Any | None = None) -> None:
        # ``policy_engine_instance`` is kept for API compatibility with older
        # call-sites but is no longer the source of truth. The allowlist is
        # always reloaded from ``tools.yaml`` so dev-time edits take effect
        # without restarting the harness.
        self._policy_engine = policy_engine_instance
        self._allowlist = _load_allowlist()
        logging.info("Loaded %d tools from %s", len(self._allowlist), _POLICY_FILE)

    def process_llm_output(self, llm_response_text: str) -> Tuple[bool, str]:
        """Mirror the Rust ``StrictToolRouter::process_llm_output`` semantics.

        Fail-closed on any parse error or non-allowlisted tool. Dual-MFA tools
        return ``PENDING_DUAL_MFA``; ``requires_human`` tools return
        ``PENDING_HUMAN``; only fully-auto-authorised tools yield ``True``.
        """
        try:
            payload = json.loads(llm_response_text)
        except json.JSONDecodeError:
            logging.error("Anti-injection: LLM produced invalid JSON.")
            return False, "ERROR: Invalid JSON response format."

        if not isinstance(payload, dict) or "tool" not in payload:
            logging.error("LLM payload missing 'tool' field.")
            return False, "ERROR: missing 'tool' field"

        raw_tool = str(payload["tool"])
        tool_name = "".join(ch for ch in raw_tool if ch.isalnum() or ch == "_")
        if not tool_name or len(tool_name) > 64:
            return False, "ERROR: invalid tool name"

        spec = self._allowlist.get(tool_name)
        if spec is None:
            logging.warning("Tool '%s' not in allowlist — BLOCKED.", tool_name)
            return False, "DENIED: tool not in allowlist"

        if spec["dual_mfa"]:
            logging.warning("Tool '%s' requires dual-operator MFA.", tool_name)
            return False, "PENDING_DUAL_MFA"

        if spec["requires_human"]:
            logging.info("Tool '%s' requires human confirmation.", tool_name)
            return False, "PENDING_HUMAN"

        logging.info("Tool '%s' auto-authorised (dev harness).", tool_name)
        return True, f"Success {tool_name} (dev-harness; no real exec)."
