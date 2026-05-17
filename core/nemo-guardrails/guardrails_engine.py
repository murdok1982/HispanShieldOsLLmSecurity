#!/usr/bin/env python3
"""
HispanShield OS — NeMo Guardrails Engine
=========================================
Wraps NVIDIA NeMo Guardrails with a graceful fallback to regex-based checks
when the nemoguardrails library is not installed.  All accept/block decisions
are written to the structured audit log at /var/log/hispanshield/guardrails.log.

Classification levels (ascending):
    UNCLASSIFIED → CONFIDENCIAL → SECRET → TS → TS/SCI
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Audit logger — structured JSON lines
# ---------------------------------------------------------------------------
LOG_PATH = Path(os.environ.get("HISPANSHIELD_GUARDRAILS_LOG",
                               "/var/log/hispanshield/guardrails.log"))

def _make_audit_logger() -> logging.Logger:
    logger = logging.getLogger("hispanshield.guardrails.audit")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        try:
            LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(str(LOG_PATH))
        except PermissionError:
            fh = logging.StreamHandler()
        fh.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(fh)
    return logger


_audit_logger = _make_audit_logger()


def _write_audit(event: Dict[str, Any]) -> None:
    event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    _audit_logger.info(json.dumps(event, ensure_ascii=False))


# ---------------------------------------------------------------------------
# Clearance ranking
# ---------------------------------------------------------------------------
CLEARANCE_RANK: Dict[str, int] = {
    "UNCLASSIFIED": 0,
    "CONFIDENCIAL":  1,
    "SECRET":        2,
    "TS":            3,
    "TS/SCI":        4,
}


# ---------------------------------------------------------------------------
# Regex-based fallback patterns  (mirrors rails.co definitions)
# ---------------------------------------------------------------------------
_JAILBREAK_PATTERNS: List[str] = [
    r"ignore\s+previous\s+instructions",
    r"ignore\s+all\s+previous",
    r"forget\s+your\s+instructions",
    r"you\s+are\s+now\s+DAN",
    r"do\s+anything\s+now",
    r"pretend\s+you\s+have\s+no\s+restrictions",
    r"pretend\s+you\s+have\s+no\s+guidelines",
    r"act\s+as\s+if\s+you\s+have\s+no",
    r"disregard\s+all\s+prior",
    r"bypass\s+your\s+safety",
    r"bypass\s+security",
    r"override\s+your\s+programming",
    r"you\s+are\s+no\s+longer",
    r"new\s+persona",
    r"developer\s+mode",
    r"\bjailbreak\b",
    r"prompt\s+injection",
    r"###SYSTEM",
    r"\[SYSTEM\]",
    r"<\|im_start\|>system",
    r"<!--\s+instructions",
]

_ADVANCED_JAILBREAK_PATTERNS: List[str] = [
    r"roleplay\s+as",
    r"play\s+the\s+role\s+of",
    r"hypothetically\s+speaking",
    r"in\s+a\s+fictional\s+world\s+where",
    r"for\s+educational\s+purposes\s+only",
    r"theoretically\s+how\s+would",
    r"without\s+your\s+safety",
    r"if\s+you\s+were\s+unrestricted",
    r"your\s+true\s+self",
    r"your\s+base\s+model",
    r"ignore\s+your\s+training",
    r"opposite\s+day",
    r"evil\s+twin",
    r"shadow\s+self",
    r"no\s+filter\s+mode",
    r"uncensored\s+mode",
    r"grandma\s+exploit",
]

_STRUCTURAL_JAILBREAK_PATTERNS: List[str] = [
    r"\n---\n",
    r"\n###\n",
    r"END\s+OF\s+INSTRUCTIONS",
    r"BEGIN\s+REAL\s+TASK",
    r"ACTUAL\s+TASK:",
    r"HIDDEN\s+PROMPT:",
    r"CONFIDENTIAL\s+INSTRUCTIONS:",
]

_NSFW_PATTERNS: List[str] = [
    r"explicit\s+content",
    r"sexual\s+content",
    r"pornographic",
    r"generate\s+nude",
    r"create\s+explicit",
]

_CMD_INJECTION_PATTERNS: List[str] = [
    r"\$\(",
    r"`[^`]+`",
    r";\s*rm\s",
    r"\|\s*bash",
    r"\|\s*sh\b",
    r"&&\s*bash",
    r"wget\s+https?://",
    r"curl\s+https?://",
    r"/bin/bash",
    r"/bin/sh",
    r"\bexec\s*\(",
    r"\bsubprocess\b",
    r"__import__",
    r"\beval\s*\(",
    r"\bos\.system\s*\(",
]

_CREDENTIAL_PATTERNS: List[str] = [
    r"password\s*:",
    r"passwd\s*:",
    r"api[_-]?key\s*:",
    r"secret[_-]?key\s*:",
    r"private[_-]?key\s*:",
    r"\bbearer\s+[A-Za-z0-9\-_\.]+",
    r"Authorization\s*:\s*",
    r"AWS_SECRET",
    r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY",
    r"token\s*=\s*['\"][A-Za-z0-9\-_\.]+['\"]",
    r"access[_-]?token\s*:",
]

_PII_PATTERNS: List[str] = [
    r"\bSSN\s*:",
    r"social\s+security",
    r"date\s+of\s+birth\s*:",
    r"\bdob\s*:",
    r"credit\s+card",
    r"passport\s+number",
    r"\bnif\s*:",
    r"\bnie\s*:",
    r"numero\s+de\s+identificacion",
]

_CLASSIFICATION_MARKERS: List[str] = [
    r"TOP\s+SECRET",
    r"TS//SCI",
    r"SECRET//NOFORN",
    r"SECRET//REL\s+TO",
    r"CONFIDENCIAL//",
    r"CLASIFICADO\s*:",
    r"RESERVADO\s*:",
    r"\[TS\]",
    r"\[SECRET\]",
    r"\[C\]//",
    r"HANDLE\s+VIA\s+COMINT",
    r"\bORCON\b",
    r"\bNOFORN\b",
    r"SCI\s+CONTROL",
]

_TOOL_INJECTION_PATTERNS: List[str] = [
    r"<tool_call>",
    r"</tool_call>",
    r"<function_calls?>",
    r"</function_calls?>",
    r'\{"tool"\s*:',
    r'\{"function"\s*:',
    r'\{"name"\s*:\s*"',
    r'"arguments"\s*:',
    r"<invoke>",
    r"</invoke>",
    r"<<<TOOL_CALL>>>",
    r"EXECUTE_FUNCTION\s*\(",
    r"CALL_TOOL\s*\(",
    r"\[FUNCTION_CALL\]",
    r"<<<FUNCTION>>>",
]


def _compile(patterns: List[str], flags: int = re.IGNORECASE) -> re.Pattern:  # type: ignore[type-arg]
    combined = "|".join(f"(?:{p})" for p in patterns)
    return re.compile(combined, flags)


_RE_JAILBREAK          = _compile(_JAILBREAK_PATTERNS)
_RE_ADV_JAILBREAK      = _compile(_ADVANCED_JAILBREAK_PATTERNS)
_RE_STRUCTURAL_JB      = _compile(_STRUCTURAL_JAILBREAK_PATTERNS)
_RE_NSFW               = _compile(_NSFW_PATTERNS)
_RE_CMD_INJECTION      = _compile(_CMD_INJECTION_PATTERNS)
_RE_CREDENTIAL         = _compile(_CREDENTIAL_PATTERNS)
_RE_PII                = _compile(_PII_PATTERNS)
_RE_CLASSIFICATION     = _compile(_CLASSIFICATION_MARKERS, flags=0)       # case-sensitive
_RE_TOOL_INJECTION     = _compile(_TOOL_INJECTION_PATTERNS, flags=0)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class GuardrailResult:
    allowed: bool
    reason: str
    modified_response: Optional[str] = None
    audit_event: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------
class HispanShieldGuardrails:
    """
    NeMo Guardrails wrapper for the HispanShield LLM pipeline.

    When ``nemoguardrails`` is installed the engine delegates to it; otherwise
    it falls back to the internal regex-based checks so that the pipeline
    continues to operate in air-gapped environments where the library may not
    be available.
    """

    BLOCKED_INPUT_RESPONSE = (
        "Solicitud bloqueada por el sistema de seguridad de HispanShield OS. "
        "Esta acción ha sido registrada y notificada al SIEM."
    )
    BLOCKED_OUTPUT_RESPONSE = (
        "Respuesta bloqueada por el sistema de seguridad de salida. "
        "El evento ha sido auditado."
    )

    def __init__(
        self,
        config_path: str = "/opt/hispanshield/core/nemo-guardrails/config",
        classification_level: str = "UNCLASSIFIED",
    ) -> None:
        self.config_path = Path(config_path)
        self.classification_level = classification_level.upper()
        self._clearance_rank = CLEARANCE_RANK.get(self.classification_level, 0)
        self._nemo_available = False
        self._rails: Any = None

        self._try_load_nemo()

    # ------------------------------------------------------------------
    # NeMo initialisation (best-effort)
    # ------------------------------------------------------------------
    def _try_load_nemo(self) -> None:
        try:
            from nemoguardrails import RailsConfig, LLMRails  # type: ignore

            if not self.config_path.is_dir():
                raise FileNotFoundError(
                    f"NeMo config directory not found: {self.config_path}"
                )
            cfg = RailsConfig.from_path(str(self.config_path))
            self._rails = LLMRails(cfg)
            self._nemo_available = True
            _write_audit({
                "event": "guardrails_init",
                "backend": "nemoguardrails",
                "config_path": str(self.config_path),
                "classification_level": self.classification_level,
            })
        except ImportError:
            _write_audit({
                "event": "guardrails_init",
                "backend": "regex_fallback",
                "reason": "nemoguardrails library not installed",
                "classification_level": self.classification_level,
            })
        except Exception as exc:
            _write_audit({
                "event": "guardrails_init",
                "backend": "regex_fallback",
                "reason": f"NeMo init failed: {exc}",
                "classification_level": self.classification_level,
            })

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def check_input(
        self,
        user_message: str,
        session_context: Optional[Dict[str, Any]] = None,
    ) -> GuardrailResult:
        """
        Run all input rails against *user_message*.

        Returns a :class:`GuardrailResult` indicating whether the message is
        allowed to proceed to the LLM.
        """
        ctx = session_context or {}
        t0 = time.monotonic()

        if self._nemo_available:
            result = await self._nemo_check_input(user_message, ctx)
        else:
            result = self._regex_check_input(user_message, ctx)

        result.audit_event.update({
            "direction": "input",
            "allowed": result.allowed,
            "reason": result.reason,
            "latency_ms": round((time.monotonic() - t0) * 1000, 2),
            "user_clearance": ctx.get("clearance_level", self.classification_level),
            "session_id": ctx.get("session_id", "unknown"),
        })
        _write_audit(result.audit_event)
        return result

    async def check_output(
        self,
        llm_response: str,
        session_context: Optional[Dict[str, Any]] = None,
    ) -> GuardrailResult:
        """
        Run all output rails against *llm_response*.

        Returns a :class:`GuardrailResult`; if ``allowed`` is ``False`` the
        caller should substitute ``modified_response`` for the raw LLM text.
        """
        ctx = session_context or {}
        t0 = time.monotonic()

        if self._nemo_available:
            result = await self._nemo_check_output(llm_response, ctx)
        else:
            result = self._regex_check_output(llm_response, ctx)

        result.audit_event.update({
            "direction": "output",
            "allowed": result.allowed,
            "reason": result.reason,
            "latency_ms": round((time.monotonic() - t0) * 1000, 2),
            "session_id": ctx.get("session_id", "unknown"),
        })
        _write_audit(result.audit_event)
        return result

    async def process(
        self,
        user_message: str,
        session_context: Optional[Dict[str, Any]] = None,
    ) -> GuardrailResult:
        """
        Combined pipeline: check input → call LLM (via NeMo) → check output.

        In regex-only mode the method only runs the input check and returns
        ``allowed=True`` with the original message so the orchestrator can
        proceed to call the LLM itself.
        """
        ctx = session_context or {}

        input_result = await self.check_input(user_message, ctx)
        if not input_result.allowed:
            return input_result

        if self._nemo_available and self._rails is not None:
            try:
                nemo_response = await self._rails.generate_async(
                    messages=[{"role": "user", "content": user_message}],
                    context=ctx,
                )
                bot_text: str = (
                    nemo_response.get("content", "")
                    if isinstance(nemo_response, dict)
                    else str(nemo_response)
                )
                output_result = await self.check_output(bot_text, ctx)
                if not output_result.allowed:
                    return output_result
                return GuardrailResult(
                    allowed=True,
                    reason="pipeline_ok",
                    modified_response=bot_text,
                    audit_event={
                        "event": "pipeline_complete",
                        "backend": "nemoguardrails",
                    },
                )
            except Exception as exc:
                _write_audit({
                    "event": "nemo_pipeline_error",
                    "error": str(exc),
                })
                # fall through to regex-only pass-through

        # Regex-only mode: caller drives the LLM invocation
        return GuardrailResult(
            allowed=True,
            reason="input_cleared_regex",
            modified_response=None,
            audit_event={
                "event": "input_cleared",
                "backend": "regex_fallback",
            },
        )

    # ------------------------------------------------------------------
    # NeMo delegation helpers
    # ------------------------------------------------------------------
    async def _nemo_check_input(
        self, user_message: str, ctx: Dict[str, Any]
    ) -> GuardrailResult:
        assert self._rails is not None
        try:
            result = await self._rails.generate_async(
                messages=[{"role": "user", "content": user_message}],
                context=ctx,
                options={"rails": "input"},
            )
            content: str = (
                result.get("content", "")
                if isinstance(result, dict)
                else str(result)
            )
            # NeMo returns the refusal message verbatim when a rail fires
            blocked = any(
                marker in content
                for marker in [
                    "Solicitud bloqueada",
                    "Acceso denegado",
                    "Solicitud rechazada",
                ]
            )
            if blocked:
                return GuardrailResult(
                    allowed=False,
                    reason="nemo_rail_blocked",
                    modified_response=content,
                    audit_event={"event": "nemo_input_blocked"},
                )
            return GuardrailResult(
                allowed=True,
                reason="nemo_input_passed",
                audit_event={"event": "nemo_input_passed"},
            )
        except Exception as exc:
            _write_audit({"event": "nemo_input_error", "error": str(exc)})
            return self._regex_check_input(user_message, ctx)

    async def _nemo_check_output(
        self, llm_response: str, ctx: Dict[str, Any]
    ) -> GuardrailResult:
        assert self._rails is not None
        try:
            result = await self._rails.generate_async(
                messages=[
                    {"role": "user", "content": "__output_check__"},
                    {"role": "assistant", "content": llm_response},
                ],
                context=ctx,
                options={"rails": "output"},
            )
            content_out: str = (
                result.get("content", llm_response)
                if isinstance(result, dict)
                else str(result)
            )
            blocked = any(
                marker in content_out
                for marker in [
                    "Respuesta bloqueada",
                    "Salida bloqueada",
                ]
            )
            if blocked:
                return GuardrailResult(
                    allowed=False,
                    reason="nemo_output_rail_blocked",
                    modified_response=self.BLOCKED_OUTPUT_RESPONSE,
                    audit_event={"event": "nemo_output_blocked"},
                )
            return GuardrailResult(
                allowed=True,
                reason="nemo_output_passed",
                modified_response=content_out,
                audit_event={"event": "nemo_output_passed"},
            )
        except Exception as exc:
            _write_audit({"event": "nemo_output_error", "error": str(exc)})
            return self._regex_check_output(llm_response, ctx)

    # ------------------------------------------------------------------
    # Regex-based fallback checks
    # ------------------------------------------------------------------
    def _regex_check_input(
        self, user_message: str, ctx: Dict[str, Any]
    ) -> GuardrailResult:
        """Pure-regex input rail check — mirrors rails.co logic exactly."""

        # 1. Hard jailbreak patterns
        m = _RE_JAILBREAK.search(user_message)
        if m:
            return GuardrailResult(
                allowed=False,
                reason=f"jailbreak_pattern_detected:{m.group()[:60]}",
                modified_response=self.BLOCKED_INPUT_RESPONSE,
                audit_event={
                    "event": "input_blocked",
                    "rail": "check_input_safety",
                    "matched": m.group()[:60],
                },
            )

        # 2. NSFW
        m = _RE_NSFW.search(user_message)
        if m:
            return GuardrailResult(
                allowed=False,
                reason=f"nsfw_content_detected:{m.group()[:60]}",
                modified_response=self.BLOCKED_INPUT_RESPONSE,
                audit_event={
                    "event": "input_blocked",
                    "rail": "check_input_safety",
                    "category": "nsfw",
                    "matched": m.group()[:60],
                },
            )

        # 3. Command injection
        m = _RE_CMD_INJECTION.search(user_message)
        if m:
            return GuardrailResult(
                allowed=False,
                reason=f"command_injection_detected:{m.group()[:60]}",
                modified_response=self.BLOCKED_INPUT_RESPONSE,
                audit_event={
                    "event": "input_blocked",
                    "rail": "check_input_safety",
                    "category": "cmd_injection",
                    "matched": m.group()[:60],
                },
            )

        # 4. Classification level check
        user_clearance = ctx.get("clearance_level", self.classification_level).upper()
        requested_level = ctx.get("requested_data_level", "UNCLASSIFIED").upper()
        user_rank = CLEARANCE_RANK.get(user_clearance, 0)
        req_rank  = CLEARANCE_RANK.get(requested_level, 0)
        if req_rank > user_rank:
            return GuardrailResult(
                allowed=False,
                reason=(
                    f"insufficient_clearance:"
                    f"{user_clearance}<{requested_level}"
                ),
                modified_response=(
                    "Acceso denegado: su nivel de acreditación no es suficiente "
                    "para acceder a información con este nivel de clasificación. "
                    "Incidente registrado."
                ),
                audit_event={
                    "event": "input_blocked",
                    "rail": "check_classification_level",
                    "user_clearance": user_clearance,
                    "requested_level": requested_level,
                },
            )

        # 5. Multi-pattern jailbreak scoring
        score = 0
        matched_adv: List[str] = []
        for m_adv in _RE_ADV_JAILBREAK.finditer(user_message):
            score += 1
            matched_adv.append(m_adv.group()[:40])
        for m_str in _RE_STRUCTURAL_JB.finditer(user_message):
            score += 2
            matched_adv.append(m_str.group()[:40])

        if score >= 2:
            return GuardrailResult(
                allowed=False,
                reason=f"multi_pattern_jailbreak_score_{score}",
                modified_response=self.BLOCKED_INPUT_RESPONSE,
                audit_event={
                    "event": "input_blocked",
                    "rail": "check_jailbreak_attempt",
                    "score": score,
                    "patterns": matched_adv,
                },
            )

        audit_flag = f"jailbreak_weak_signal_score_{score}" if score == 1 else None
        return GuardrailResult(
            allowed=True,
            reason="input_passed_regex",
            audit_event={
                "event": "input_allowed",
                "backend": "regex_fallback",
                **({"flag": audit_flag} if audit_flag else {}),
            },
        )

    def _regex_check_output(
        self, llm_response: str, ctx: Dict[str, Any]
    ) -> GuardrailResult:
        """Pure-regex output rail check — mirrors rails.co logic exactly."""

        # 1. Credential leak
        m = _RE_CREDENTIAL.search(llm_response)
        if m:
            return GuardrailResult(
                allowed=False,
                reason=f"credential_in_output:{m.group()[:60]}",
                modified_response=self.BLOCKED_OUTPUT_RESPONSE,
                audit_event={
                    "event": "output_blocked",
                    "rail": "check_output_safety",
                    "category": "credential",
                    "matched": m.group()[:60],
                },
            )

        # 2. PII
        m = _RE_PII.search(llm_response)
        if m:
            return GuardrailResult(
                allowed=False,
                reason=f"pii_in_output:{m.group()[:60]}",
                modified_response=self.BLOCKED_OUTPUT_RESPONSE,
                audit_event={
                    "event": "output_blocked",
                    "rail": "check_output_safety",
                    "category": "pii",
                    "matched": m.group()[:60],
                },
            )

        # 3. Classification markers (case-sensitive scan)
        m = _RE_CLASSIFICATION.search(llm_response)
        if m:
            return GuardrailResult(
                allowed=False,
                reason=f"classified_marker_in_output:{m.group()[:60]}",
                modified_response=self.BLOCKED_OUTPUT_RESPONSE,
                audit_event={
                    "event": "output_blocked",
                    "rail": "check_classified_data_leakage",
                    "marker": m.group()[:60],
                },
            )

        # 4. Tool injection
        m = _RE_TOOL_INJECTION.search(llm_response)
        if m:
            return GuardrailResult(
                allowed=False,
                reason=f"tool_injection_in_output:{m.group()[:60]}",
                modified_response=self.BLOCKED_OUTPUT_RESPONSE,
                audit_event={
                    "event": "output_blocked",
                    "rail": "check_tool_injection",
                    "pattern": m.group()[:60],
                },
            )

        # 5. Sensitive network info heuristic (soft flag, don't block)
        sensitive_net_kws = [
            "network diagram", "internal subnet", "vpn config",
            "firewall rule", " acl ", "routing table",
        ]
        lower_resp = llm_response.lower()
        has_net_kw = any(kw in lower_resp for kw in sensitive_net_kws)
        # RFC-1918 IP heuristic
        has_private_ip = bool(
            re.search(
                r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
                r"|192\.168\.\d{1,3}\.\d{1,3})\b",
                llm_response,
            )
        )
        audit_flag = None
        if has_net_kw and has_private_ip:
            audit_flag = "sensitive_network_info_in_output"
            _write_audit({
                "event": "output_flagged",
                "rail": "check_classified_data_leakage",
                "flag": audit_flag,
                "session_id": ctx.get("session_id", "unknown"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        return GuardrailResult(
            allowed=True,
            reason="output_passed_regex",
            audit_event={
                "event": "output_allowed",
                "backend": "regex_fallback",
                **({"flag": audit_flag} if audit_flag else {}),
            },
        )


# ---------------------------------------------------------------------------
# CLI entry-point for smoke-testing
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="HispanShield Guardrails Engine — smoke test"
    )
    parser.add_argument(
        "--config",
        default="/opt/hispanshield/core/nemo-guardrails/config",
        help="Path to NeMo config directory",
    )
    parser.add_argument(
        "--clearance",
        default="UNCLASSIFIED",
        choices=list(CLEARANCE_RANK.keys()),
    )
    parser.add_argument("--message", default="Hello, Aegis. What is the weather?")
    args = parser.parse_args()

    engine = HispanShieldGuardrails(
        config_path=args.config,
        classification_level=args.clearance,
    )
    ctx = {"clearance_level": args.clearance, "session_id": "smoke-test-cli"}

    async def _run() -> None:
        r = await engine.check_input(args.message, ctx)
        print(json.dumps(
            {
                "allowed": r.allowed,
                "reason": r.reason,
                "modified_response": r.modified_response,
            },
            indent=2,
            ensure_ascii=False,
        ))

    asyncio.run(_run())
