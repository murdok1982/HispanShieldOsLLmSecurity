#!/usr/bin/env python3
"""
HispanShield OS — GRC Compliance Engine
========================================
Automated control-checking engine for NIST SP 800-53, DISA STIG (Linux), and
HispanShield custom controls.  Each control is implemented as a deterministic
method that inspects the running system and returns a :class:`ControlResult`.

Usage (CLI)
-----------
    python3 grc_engine.py --format text
    python3 grc_engine.py --format json --output /var/log/hispanshield/compliance/grc_report.json
    python3 grc_engine.py --framework NIST-800-53 --format text

Environment
-----------
HISPANSHIELD_GRC_SYSTEM_ROOT   override filesystem root (default /)
HISPANSHIELD_GRC_LOG_DIR       compliance log directory
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional

# ---------------------------------------------------------------------------
# Enums and dataclasses
# ---------------------------------------------------------------------------

class ControlStatus(Enum):
    PASS           = "PASS"
    FAIL           = "FAIL"
    NOT_APPLICABLE = "N/A"
    MANUAL_REVIEW  = "MANUAL_REVIEW"


@dataclass
class ControlResult:
    control_id:  str
    framework:   str          # "NIST-800-53" | "DISA-STIG" | "ICD-503" | "HISPANSHIELD"
    title:       str
    status:      ControlStatus
    evidence:    str
    remediation: Optional[str]
    severity:    str          # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    timestamp:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_log = logging.getLogger("hispanshield.grc")


def _run(cmd: str, *, timeout: int = 10) -> tuple[int, str, str]:
    """Execute *cmd* via the shell; return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "command timed out"
    except Exception as exc:
        return -1, "", str(exc)


def _file_contains(path: Path, pattern: str, *, flags: int = 0) -> bool:
    try:
        text = path.read_text(errors="replace")
        return bool(re.search(pattern, text, flags))
    except (OSError, IOError):
        return False


def _sysctl(key: str) -> Optional[str]:
    rc, out, _ = _run(f"sysctl -n {key}")
    return out if rc == 0 else None


def _systemctl_active(service: str) -> bool:
    rc, _, _ = _run(f"systemctl is-active --quiet {service}")
    return rc == 0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stat_octal(path: Path) -> Optional[str]:
    try:
        return oct(path.stat().st_mode)[-3:]
    except OSError:
        return None


def _stat_uid(path: Path) -> Optional[int]:
    try:
        return path.stat().st_uid
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class HispanShieldGRCEngine:
    """
    Automated GRC compliance engine.

    Parameters
    ----------
    system_root:
        Filesystem root to prefix all absolute paths.  Override to ``/mnt/target``
        when scanning a mounted image.
    log_dir:
        Directory where compliance artefacts are written.
    """

    FRAMEWORKS = ("NIST-800-53", "DISA-STIG", "HISPANSHIELD")

    def __init__(
        self,
        system_root: str = "/",
        log_dir: str = "/var/log/hispanshield/compliance",
    ) -> None:
        self.system_root = Path(system_root)
        self.log_dir = Path(log_dir)
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            pass

        # Registry: list of (framework, check_method)
        self._registry: List[tuple[str, Callable[[], ControlResult]]] = []
        self._register_all()

    # ------------------------------------------------------------------
    # Registry
    # ------------------------------------------------------------------
    def _reg(self, framework: str, method: Callable[[], ControlResult]) -> None:
        self._registry.append((framework, method))

    def _register_all(self) -> None:
        # NIST 800-53
        for m in [
            self._check_ac2, self._check_ac17, self._check_au2, self._check_au9,
            self._check_ia2_1, self._check_sc28, self._check_si7, self._check_sc8,
        ]:
            self._reg("NIST-800-53", m)

        # DISA STIG
        for m in [
            self._check_v230221, self._check_v230228, self._check_v230264,
            self._check_v230487, self._check_v230492,
        ]:
            self._reg("DISA-STIG", m)

        # HispanShield custom
        for m in [
            self._check_hs001, self._check_hs002, self._check_hs003,
            self._check_hs004, self._check_hs005,
        ]:
            self._reg("HISPANSHIELD", m)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def run_all_controls(self) -> List[ControlResult]:
        """Execute every registered control and return results."""
        results: List[ControlResult] = []
        for _fw, method in self._registry:
            try:
                results.append(method())
            except Exception as exc:
                _log.error("Control check %s raised: %s", method.__name__, exc)
        return results

    def run_framework(self, framework: str) -> List[ControlResult]:
        """Run only controls belonging to *framework*."""
        results: List[ControlResult] = []
        for fw, method in self._registry:
            if fw == framework:
                try:
                    results.append(method())
                except Exception as exc:
                    _log.error("Control check %s raised: %s", method.__name__, exc)
        return results

    def calculate_score(self, results: List[ControlResult]) -> Dict[str, object]:
        """Return pass/fail summary and percentage score."""
        total   = len(results)
        passed  = sum(1 for r in results if r.status == ControlStatus.PASS)
        failed  = sum(1 for r in results if r.status == ControlStatus.FAIL)
        na      = sum(1 for r in results if r.status == ControlStatus.NOT_APPLICABLE)
        manual  = sum(1 for r in results if r.status == ControlStatus.MANUAL_REVIEW)
        scorable = total - na
        score_pct = round((passed / scorable * 100), 1) if scorable else 0.0
        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "not_applicable": na,
            "manual_review": manual,
            "score_pct": score_pct,
        }

    def generate_report(
        self,
        results: List[ControlResult],
        fmt: str = "json",
    ) -> str:
        """
        Render compliance findings as a string.

        Parameters
        ----------
        results:
            List of :class:`ControlResult` objects.
        fmt:
            ``"json"`` or ``"text"``.
        """
        if fmt == "json":
            return self._report_json(results)
        return self._report_text(results)

    # ------------------------------------------------------------------
    # Report renderers
    # ------------------------------------------------------------------
    def _report_json(self, results: List[ControlResult]) -> str:
        score = self.calculate_score(results)
        payload = {
            "generated_at": _now(),
            "score": score,
            "controls": [
                {
                    **asdict(r),
                    "status": r.status.value,
                }
                for r in results
            ],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    def _report_text(self, results: List[ControlResult]) -> str:
        score = self.calculate_score(results)
        sep   = "=" * 78
        lines: List[str] = [
            sep,
            "  HispanShield OS — GRC Compliance Report",
            f"  Generated : {_now()}",
            f"  Score     : {score['score_pct']}%  "
            f"({score['passed']} PASS / {score['failed']} FAIL / "
            f"{score['not_applicable']} N/A / {score['manual_review']} MANUAL)",
            sep,
            "",
        ]

        # Group by framework
        by_fw: Dict[str, List[ControlResult]] = {}
        for r in results:
            by_fw.setdefault(r.framework, []).append(r)

        for fw, fw_results in by_fw.items():
            fw_score = self.calculate_score(fw_results)
            lines.append(f"  [{fw}]  score: {fw_score['score_pct']}%")
            lines.append("-" * 78)
            lines.append(
                f"  {'Control':<18} {'Severity':<10} {'Status':<15} Title"
            )
            lines.append("-" * 78)
            for r in fw_results:
                status_str = r.status.value
                lines.append(
                    f"  {r.control_id:<18} {r.severity:<10} {status_str:<15} {r.title}"
                )
            lines.append("")

        # Findings detail
        lines += [sep, "  FINDINGS DETAIL", sep, ""]
        for r in results:
            if r.status in (ControlStatus.FAIL, ControlStatus.MANUAL_REVIEW):
                lines.append(f"  [{r.status.value}] {r.control_id} — {r.title}")
                lines.append(f"    Framework  : {r.framework}")
                lines.append(f"    Severity   : {r.severity}")
                lines.append(f"    Evidence   : {r.evidence}")
                if r.remediation:
                    lines.append(f"    Remediation: {r.remediation}")
                lines.append("")

        lines.append(sep)
        return "\n".join(lines)

    # ==================================================================
    # NIST SP 800-53 control checks
    # ==================================================================

    def _check_ac2(self) -> ControlResult:
        """AC-2: Account Management — aegis service accounts exist with locked passwords."""
        issues: List[str] = []

        # Check aegis_agent user
        rc1, out1, _ = _run("getent passwd aegis_agent")
        if rc1 != 0:
            issues.append("user aegis_agent not found")

        # Check aegis group
        rc2, out2, _ = _run("getent group aegis")
        if rc2 != 0:
            issues.append("group aegis not found")

        # Check password locked (shadow entry starts with ! or *)
        rc3, shadow_entry, _ = _run("getent shadow aegis_agent 2>/dev/null")
        if rc3 == 0 and shadow_entry:
            pw_field = shadow_entry.split(":")[1] if ":" in shadow_entry else ""
            if not pw_field.startswith(("!", "*")):
                issues.append("aegis_agent password is not locked")
        elif rc3 != 0 and rc1 == 0:
            issues.append("cannot read /etc/shadow (need root?)")

        if issues:
            return ControlResult(
                control_id="AC-2",
                framework="NIST-800-53",
                title="Account Management",
                status=ControlStatus.FAIL,
                evidence="; ".join(issues),
                remediation=(
                    "Run: useradd --system --shell /sbin/nologin aegis_agent && "
                    "groupadd aegis && usermod -aG aegis aegis_agent && "
                    "passwd -l aegis_agent"
                ),
                severity="HIGH",
            )
        return ControlResult(
            control_id="AC-2",
            framework="NIST-800-53",
            title="Account Management",
            status=ControlStatus.PASS,
            evidence=f"aegis_agent present and group aegis found: {out2.strip()}",
            remediation=None,
            severity="HIGH",
        )

    def _check_ac17(self) -> ControlResult:
        """AC-17: Remote Access — SSH PasswordAuthentication=no enforced."""
        sshd_config = self.system_root / "etc" / "ssh" / "sshd_config"
        sshd_conf_d = self.system_root / "etc" / "ssh" / "sshd_config.d"

        def _check_file(p: Path) -> bool:
            return _file_contains(
                p,
                r"^\s*PasswordAuthentication\s+no",
                flags=re.IGNORECASE | re.MULTILINE,
            )

        found = False
        if sshd_config.is_file():
            found = _check_file(sshd_config)

        if not found and sshd_conf_d.is_dir():
            for drop_in in sshd_conf_d.glob("*.conf"):
                if _check_file(drop_in):
                    found = True
                    break

        if found:
            return ControlResult(
                control_id="AC-17",
                framework="NIST-800-53",
                title="Remote Access — SSH password auth disabled",
                status=ControlStatus.PASS,
                evidence="PasswordAuthentication no found in sshd_config",
                remediation=None,
                severity="HIGH",
            )
        return ControlResult(
            control_id="AC-17",
            framework="NIST-800-53",
            title="Remote Access — SSH password auth disabled",
            status=ControlStatus.FAIL,
            evidence="PasswordAuthentication no not found in /etc/ssh/sshd_config",
            remediation=(
                "Add 'PasswordAuthentication no' to /etc/ssh/sshd_config "
                "and restart sshd."
            ),
            severity="HIGH",
        )

    def _check_au2(self) -> ControlResult:
        """AU-2: Audit Events — auditd service active."""
        active = _systemctl_active("auditd")
        if active:
            return ControlResult(
                control_id="AU-2",
                framework="NIST-800-53",
                title="Audit Events — auditd active",
                status=ControlStatus.PASS,
                evidence="systemctl is-active auditd returned 0",
                remediation=None,
                severity="HIGH",
            )
        return ControlResult(
            control_id="AU-2",
            framework="NIST-800-53",
            title="Audit Events — auditd active",
            status=ControlStatus.FAIL,
            evidence="auditd is not active (systemctl is-active returned non-zero)",
            remediation="systemctl enable --now auditd",
            severity="HIGH",
        )

    def _check_au9(self) -> ControlResult:
        """AU-9: Protection of Audit Information — log dir perms 700 owned by root."""
        audit_log_dir = self.system_root / "var" / "log" / "audit"
        alt_dir = self.system_root / "var" / "log" / "hispanshield"

        target = audit_log_dir if audit_log_dir.exists() else alt_dir
        if not target.exists():
            return ControlResult(
                control_id="AU-9",
                framework="NIST-800-53",
                title="Protection of Audit Information",
                status=ControlStatus.FAIL,
                evidence=f"Audit log directory not found at {audit_log_dir} or {alt_dir}",
                remediation=f"mkdir -p {audit_log_dir} && chmod 700 {audit_log_dir} && chown root:root {audit_log_dir}",
                severity="MEDIUM",
            )

        perms = _stat_octal(target)
        uid   = _stat_uid(target)
        issues: List[str] = []
        if perms != "700":
            issues.append(f"permissions are {perms}, expected 700")
        if uid != 0:
            issues.append(f"owner uid is {uid}, expected 0 (root)")

        if issues:
            return ControlResult(
                control_id="AU-9",
                framework="NIST-800-53",
                title="Protection of Audit Information",
                status=ControlStatus.FAIL,
                evidence=f"{target}: {'; '.join(issues)}",
                remediation=f"chmod 700 {target} && chown root:root {target}",
                severity="MEDIUM",
            )
        return ControlResult(
            control_id="AU-9",
            framework="NIST-800-53",
            title="Protection of Audit Information",
            status=ControlStatus.PASS,
            evidence=f"{target}: permissions=700, owner=root",
            remediation=None,
            severity="MEDIUM",
        )

    def _check_ia2_1(self) -> ControlResult:
        """IA-2(1): Multi-Factor Authentication — pam_u2f or pam_pkcs11 configured."""
        pam_dir = self.system_root / "etc" / "pam.d"
        if not pam_dir.is_dir():
            return ControlResult(
                control_id="IA-2(1)",
                framework="NIST-800-53",
                title="MFA — pam_u2f or pam_pkcs11",
                status=ControlStatus.NOT_APPLICABLE,
                evidence="/etc/pam.d not found",
                remediation=None,
                severity="CRITICAL",
            )

        mfa_pattern = re.compile(r"pam_(u2f|pkcs11)\.so", re.IGNORECASE)
        found_files: List[str] = []
        for pam_file in pam_dir.iterdir():
            if pam_file.is_file():
                try:
                    if mfa_pattern.search(pam_file.read_text(errors="replace")):
                        found_files.append(pam_file.name)
                except OSError:
                    pass

        if found_files:
            return ControlResult(
                control_id="IA-2(1)",
                framework="NIST-800-53",
                title="MFA — pam_u2f or pam_pkcs11",
                status=ControlStatus.PASS,
                evidence=f"pam_u2f/pam_pkcs11 found in: {', '.join(found_files)}",
                remediation=None,
                severity="CRITICAL",
            )
        return ControlResult(
            control_id="IA-2(1)",
            framework="NIST-800-53",
            title="MFA — pam_u2f or pam_pkcs11",
            status=ControlStatus.FAIL,
            evidence="No pam_u2f.so or pam_pkcs11.so found in /etc/pam.d/",
            remediation=(
                "Install libpam-u2f (apt) and configure it in /etc/pam.d/common-auth. "
                "Or install libpam-pkcs11 for smart-card-based MFA."
            ),
            severity="CRITICAL",
        )

    def _check_sc28(self) -> ControlResult:
        """SC-28: Protection of Information at Rest — LUKS encrypted partitions."""
        rc, out, _ = _run("lsblk -o NAME,TYPE,FSTYPE --json 2>/dev/null || lsblk -o NAME,TYPE,FSTYPE")
        if rc != 0:
            # Try dmsetup as fallback
            rc2, out2, _ = _run("dmsetup ls --target crypt 2>/dev/null")
            if rc2 == 0 and out2:
                return ControlResult(
                    control_id="SC-28",
                    framework="NIST-800-53",
                    title="Protection of Information at Rest — LUKS encryption",
                    status=ControlStatus.PASS,
                    evidence=f"dm-crypt targets found via dmsetup: {out2[:200]}",
                    remediation=None,
                    severity="CRITICAL",
                )
            return ControlResult(
                control_id="SC-28",
                framework="NIST-800-53",
                title="Protection of Information at Rest — LUKS encryption",
                status=ControlStatus.MANUAL_REVIEW,
                evidence="lsblk and dmsetup unavailable — manual verification required",
                remediation="Verify LUKS encryption via cryptsetup status <device>",
                severity="CRITICAL",
            )

        # Look for LUKS or crypto_LUKS in lsblk output
        if re.search(r"crypto_LUKS|crypt\b", out, re.IGNORECASE):
            return ControlResult(
                control_id="SC-28",
                framework="NIST-800-53",
                title="Protection of Information at Rest — LUKS encryption",
                status=ControlStatus.PASS,
                evidence="LUKS/crypto_LUKS devices detected in lsblk output",
                remediation=None,
                severity="CRITICAL",
            )

        # Also check cryptsetup status directly
        rc3, out3, _ = _run("cryptsetup status / 2>/dev/null; cryptsetup luksDump $(lsblk -no pkname $(findmnt -n -o SOURCE /) 2>/dev/null | head -1) 2>/dev/null | head -5")
        if "LUKS" in out3 or "cipher" in out3.lower():
            return ControlResult(
                control_id="SC-28",
                framework="NIST-800-53",
                title="Protection of Information at Rest — LUKS encryption",
                status=ControlStatus.PASS,
                evidence="LUKS header detected via cryptsetup",
                remediation=None,
                severity="CRITICAL",
            )

        return ControlResult(
            control_id="SC-28",
            framework="NIST-800-53",
            title="Protection of Information at Rest — LUKS encryption",
            status=ControlStatus.FAIL,
            evidence="No LUKS-encrypted partitions detected",
            remediation=(
                "Encrypt sensitive partitions with LUKS: "
                "cryptsetup luksFormat /dev/<device>"
            ),
            severity="CRITICAL",
        )

    def _check_si7(self) -> ControlResult:
        """SI-7: Software and Firmware Integrity — IMA policy loaded."""
        ima_policy = self.system_root / "sys" / "kernel" / "security" / "ima" / "policy"
        if not ima_policy.exists():
            return ControlResult(
                control_id="SI-7",
                framework="NIST-800-53",
                title="Software & Firmware Integrity — IMA policy",
                status=ControlStatus.FAIL,
                evidence=f"{ima_policy} does not exist — IMA not enabled in kernel",
                remediation=(
                    "Enable IMA in kernel cmdline: ima_policy=tcb "
                    "and load a policy: echo <rules> > /sys/kernel/security/ima/policy"
                ),
                severity="HIGH",
            )
        try:
            content = ima_policy.read_text(errors="replace").strip()
        except OSError as exc:
            content = ""
            _log.debug("Cannot read IMA policy: %s", exc)

        if content:
            return ControlResult(
                control_id="SI-7",
                framework="NIST-800-53",
                title="Software & Firmware Integrity — IMA policy",
                status=ControlStatus.PASS,
                evidence="IMA policy file exists and is non-empty",
                remediation=None,
                severity="HIGH",
            )
        return ControlResult(
            control_id="SI-7",
            framework="NIST-800-53",
            title="Software & Firmware Integrity — IMA policy",
            status=ControlStatus.FAIL,
            evidence="IMA policy file exists but is empty — no rules loaded",
            remediation=(
                "Load IMA measurement/appraisal rules: "
                "echo 'measure func=FILE_CHECK mask=MAY_READ uid=0' "
                "> /sys/kernel/security/ima/policy"
            ),
            severity="HIGH",
        )

    def _check_sc8(self) -> ControlResult:
        """SC-8: Transmission Confidentiality — TLS 1.2+ enforced in openssl.cnf."""
        openssl_cnf = self.system_root / "etc" / "ssl" / "openssl.cnf"
        if not openssl_cnf.is_file():
            return ControlResult(
                control_id="SC-8",
                framework="NIST-800-53",
                title="Transmission Confidentiality — TLS 1.2+ minimum",
                status=ControlStatus.MANUAL_REVIEW,
                evidence="/etc/ssl/openssl.cnf not found",
                remediation="Create /etc/ssl/openssl.cnf with MinProtocol = TLSv1.2",
                severity="HIGH",
            )

        min_proto_match = re.search(
            r"^\s*MinProtocol\s*=\s*(.+)$",
            openssl_cnf.read_text(errors="replace"),
            re.IGNORECASE | re.MULTILINE,
        )
        if not min_proto_match:
            return ControlResult(
                control_id="SC-8",
                framework="NIST-800-53",
                title="Transmission Confidentiality — TLS 1.2+ minimum",
                status=ControlStatus.FAIL,
                evidence="MinProtocol not set in /etc/ssl/openssl.cnf",
                remediation="Add 'MinProtocol = TLSv1.2' under [system_default_sect] in openssl.cnf",
                severity="HIGH",
            )

        proto_val = min_proto_match.group(1).strip()
        # Accept TLSv1.2 or TLSv1.3
        allowed_protos = {"TLSv1.2", "TLSv1.3", "TLS1.2", "TLS1.3"}
        if any(p in proto_val for p in allowed_protos):
            return ControlResult(
                control_id="SC-8",
                framework="NIST-800-53",
                title="Transmission Confidentiality — TLS 1.2+ minimum",
                status=ControlStatus.PASS,
                evidence=f"MinProtocol = {proto_val}",
                remediation=None,
                severity="HIGH",
            )
        return ControlResult(
            control_id="SC-8",
            framework="NIST-800-53",
            title="Transmission Confidentiality — TLS 1.2+ minimum",
            status=ControlStatus.FAIL,
            evidence=f"MinProtocol = {proto_val} (below TLSv1.2)",
            remediation="Set MinProtocol = TLSv1.2 or TLSv1.3 in /etc/ssl/openssl.cnf",
            severity="HIGH",
        )

    # ==================================================================
    # DISA STIG control checks
    # ==================================================================

    def _check_v230221(self) -> ControlResult:
        """V-230221: kernel.dmesg_restrict=1."""
        val = _sysctl("kernel.dmesg_restrict")
        if val == "1":
            return ControlResult(
                control_id="V-230221",
                framework="DISA-STIG",
                title="kernel.dmesg_restrict=1",
                status=ControlStatus.PASS,
                evidence="kernel.dmesg_restrict = 1",
                remediation=None,
                severity="MEDIUM",
            )
        return ControlResult(
            control_id="V-230221",
            framework="DISA-STIG",
            title="kernel.dmesg_restrict=1",
            status=ControlStatus.FAIL,
            evidence=f"kernel.dmesg_restrict = {val!r} (expected 1)",
            remediation=(
                "echo 'kernel.dmesg_restrict = 1' >> /etc/sysctl.d/99-hispanshield.conf "
                "&& sysctl -p /etc/sysctl.d/99-hispanshield.conf"
            ),
            severity="MEDIUM",
        )

    def _check_v230228(self) -> ControlResult:
        """V-230228: kernel.kptr_restrict=2."""
        val = _sysctl("kernel.kptr_restrict")
        if val == "2":
            return ControlResult(
                control_id="V-230228",
                framework="DISA-STIG",
                title="kernel.kptr_restrict=2",
                status=ControlStatus.PASS,
                evidence="kernel.kptr_restrict = 2",
                remediation=None,
                severity="MEDIUM",
            )
        return ControlResult(
            control_id="V-230228",
            framework="DISA-STIG",
            title="kernel.kptr_restrict=2",
            status=ControlStatus.FAIL,
            evidence=f"kernel.kptr_restrict = {val!r} (expected 2)",
            remediation=(
                "echo 'kernel.kptr_restrict = 2' >> /etc/sysctl.d/99-hispanshield.conf "
                "&& sysctl -p /etc/sysctl.d/99-hispanshield.conf"
            ),
            severity="MEDIUM",
        )

    def _check_v230264(self) -> ControlResult:
        """V-230264: /tmp mounted with noexec option."""
        rc, out, _ = _run("findmnt -n -o OPTIONS /tmp 2>/dev/null || mount | grep ' on /tmp '")
        if "noexec" in out:
            return ControlResult(
                control_id="V-230264",
                framework="DISA-STIG",
                title="/tmp noexec mount option",
                status=ControlStatus.PASS,
                evidence=f"/tmp mount options include noexec: {out[:120]}",
                remediation=None,
                severity="MEDIUM",
            )
        if not out:
            return ControlResult(
                control_id="V-230264",
                framework="DISA-STIG",
                title="/tmp noexec mount option",
                status=ControlStatus.MANUAL_REVIEW,
                evidence="Could not determine /tmp mount options — manual review required",
                remediation="Add noexec to /tmp mount options in /etc/fstab",
                severity="MEDIUM",
            )
        return ControlResult(
            control_id="V-230264",
            framework="DISA-STIG",
            title="/tmp noexec mount option",
            status=ControlStatus.FAIL,
            evidence=f"/tmp does not have noexec: {out[:120]}",
            remediation=(
                "Edit /etc/fstab: add noexec to /tmp options, then remount: "
                "mount -o remount,noexec /tmp"
            ),
            severity="MEDIUM",
        )

    def _check_v230487(self) -> ControlResult:
        """V-230487: auditd max_log_file_action=ROTATE."""
        auditd_conf = self.system_root / "etc" / "audit" / "auditd.conf"
        if not auditd_conf.is_file():
            return ControlResult(
                control_id="V-230487",
                framework="DISA-STIG",
                title="auditd max_log_file_action=ROTATE",
                status=ControlStatus.FAIL,
                evidence="/etc/audit/auditd.conf not found",
                remediation="Install auditd: apt install auditd",
                severity="MEDIUM",
            )

        m = re.search(
            r"^\s*max_log_file_action\s*=\s*(.+)$",
            auditd_conf.read_text(errors="replace"),
            re.IGNORECASE | re.MULTILINE,
        )
        if not m:
            return ControlResult(
                control_id="V-230487",
                framework="DISA-STIG",
                title="auditd max_log_file_action=ROTATE",
                status=ControlStatus.FAIL,
                evidence="max_log_file_action not set in auditd.conf",
                remediation="Add 'max_log_file_action = ROTATE' to /etc/audit/auditd.conf",
                severity="MEDIUM",
            )

        val = m.group(1).strip().upper()
        if val == "ROTATE":
            return ControlResult(
                control_id="V-230487",
                framework="DISA-STIG",
                title="auditd max_log_file_action=ROTATE",
                status=ControlStatus.PASS,
                evidence=f"max_log_file_action = {val}",
                remediation=None,
                severity="MEDIUM",
            )
        return ControlResult(
            control_id="V-230487",
            framework="DISA-STIG",
            title="auditd max_log_file_action=ROTATE",
            status=ControlStatus.FAIL,
            evidence=f"max_log_file_action = {val} (expected ROTATE)",
            remediation=(
                "Set 'max_log_file_action = ROTATE' in /etc/audit/auditd.conf "
                "and restart auditd."
            ),
            severity="MEDIUM",
        )

    def _check_v230492(self) -> ControlResult:
        """V-230492: AppArmor profiles loaded."""
        if not shutil.which("aa-status"):
            # Try apparmor_status as alternative
            rc, out, _ = _run("apparmor_status 2>/dev/null | head -5")
            if rc != 0:
                return ControlResult(
                    control_id="V-230492",
                    framework="DISA-STIG",
                    title="AppArmor profiles loaded",
                    status=ControlStatus.FAIL,
                    evidence="aa-status and apparmor_status not found — AppArmor not installed",
                    remediation="apt install apparmor apparmor-utils && systemctl enable apparmor",
                    severity="HIGH",
                )
        else:
            rc, out, _ = _run("aa-status --json 2>/dev/null || aa-status 2>/dev/null | head -10")

        if rc != 0:
            return ControlResult(
                control_id="V-230492",
                framework="DISA-STIG",
                title="AppArmor profiles loaded",
                status=ControlStatus.FAIL,
                evidence=f"aa-status returned non-zero: {out[:200]}",
                remediation="systemctl enable --now apparmor && aa-enforce /etc/apparmor.d/*",
                severity="HIGH",
            )

        # Parse JSON if available
        profiles_enforced = 0
        if out.startswith("{"):
            try:
                data = json.loads(out)
                profiles_enforced = len(data.get("profiles", {}).get("enforce", {}))
            except json.JSONDecodeError:
                pass
        else:
            m = re.search(r"(\d+)\s+profiles? are in enforce mode", out)
            if m:
                profiles_enforced = int(m.group(1))

        if profiles_enforced > 0:
            return ControlResult(
                control_id="V-230492",
                framework="DISA-STIG",
                title="AppArmor profiles loaded",
                status=ControlStatus.PASS,
                evidence=f"{profiles_enforced} AppArmor profile(s) in enforce mode",
                remediation=None,
                severity="HIGH",
            )
        return ControlResult(
            control_id="V-230492",
            framework="DISA-STIG",
            title="AppArmor profiles loaded",
            status=ControlStatus.FAIL,
            evidence="No AppArmor profiles in enforce mode",
            remediation="aa-enforce /etc/apparmor.d/* && systemctl reload apparmor",
            severity="HIGH",
        )

    # ==================================================================
    # HispanShield Custom control checks
    # ==================================================================

    def _check_hs001(self) -> ControlResult:
        """HS-001: aegis-sentinel service active."""
        active = _systemctl_active("aegis-sentinel")
        if active:
            return ControlResult(
                control_id="HS-001",
                framework="HISPANSHIELD",
                title="aegis-sentinel service active",
                status=ControlStatus.PASS,
                evidence="systemctl is-active aegis-sentinel: active",
                remediation=None,
                severity="CRITICAL",
            )
        return ControlResult(
            control_id="HS-001",
            framework="HISPANSHIELD",
            title="aegis-sentinel service active",
            status=ControlStatus.FAIL,
            evidence="aegis-sentinel service is not active",
            remediation="systemctl enable --now aegis-sentinel",
            severity="CRITICAL",
        )

    def _check_hs002(self) -> ControlResult:
        """HS-002: Bearer token file exists with permissions 400."""
        token_path = self.system_root / "etc" / "hispanshield" / "secrets" / "sentinel.token"
        if not token_path.exists():
            return ControlResult(
                control_id="HS-002",
                framework="HISPANSHIELD",
                title="Bearer token file exists with 400 permissions",
                status=ControlStatus.FAIL,
                evidence=f"{token_path} does not exist",
                remediation=(
                    "Create the token: openssl rand -hex 32 > "
                    f"{token_path} && chmod 400 {token_path} && chown root:root {token_path}"
                ),
                severity="CRITICAL",
            )

        perms = _stat_octal(token_path)
        uid   = _stat_uid(token_path)
        issues: List[str] = []
        if perms != "400":
            issues.append(f"permissions are {perms}, expected 400")
        if uid != 0:
            issues.append(f"owner uid is {uid}, expected 0 (root)")

        if issues:
            return ControlResult(
                control_id="HS-002",
                framework="HISPANSHIELD",
                title="Bearer token file exists with 400 permissions",
                status=ControlStatus.FAIL,
                evidence=f"{token_path}: {'; '.join(issues)}",
                remediation=f"chmod 400 {token_path} && chown root:root {token_path}",
                severity="CRITICAL",
            )
        return ControlResult(
            control_id="HS-002",
            framework="HISPANSHIELD",
            title="Bearer token file exists with 400 permissions",
            status=ControlStatus.PASS,
            evidence=f"{token_path}: permissions=400, owner=root",
            remediation=None,
            severity="CRITICAL",
        )

    def _check_hs003(self) -> ControlResult:
        """HS-003: llama-server only listens on 127.0.0.1."""
        # Try ss first, then netstat
        rc, out, _ = _run(
            "ss -tlnp 2>/dev/null | grep -E '(llama|llama-server|llama_server)'"
        )
        if rc != 0 or not out:
            rc, out, _ = _run(
                "netstat -tlnp 2>/dev/null | grep -E '(llama|llama-server|llama_server)'"
            )

        if not out:
            # Process might not be running — check if binary exists
            rc2, _, _ = _run("pgrep -x llama-server 2>/dev/null || pgrep -f llama-server 2>/dev/null")
            if rc2 != 0:
                return ControlResult(
                    control_id="HS-003",
                    framework="HISPANSHIELD",
                    title="llama-server bound to 127.0.0.1 only",
                    status=ControlStatus.NOT_APPLICABLE,
                    evidence="llama-server process not detected — service may not be running",
                    remediation=None,
                    severity="HIGH",
                )
            return ControlResult(
                control_id="HS-003",
                framework="HISPANSHIELD",
                title="llama-server bound to 127.0.0.1 only",
                status=ControlStatus.MANUAL_REVIEW,
                evidence="llama-server process found but cannot determine listening address",
                remediation="Ensure llama-server is started with --host 127.0.0.1",
                severity="HIGH",
            )

        # Check that no line shows 0.0.0.0 or ::
        lines = out.strip().splitlines()
        exposed: List[str] = []
        for line in lines:
            if re.search(r"0\.0\.0\.0|::|LISTEN.*0\.0\.0", line):
                # Make sure it's not the loopback
                if not re.search(r"127\.0\.0\.1", line):
                    exposed.append(line.strip())

        if exposed:
            return ControlResult(
                control_id="HS-003",
                framework="HISPANSHIELD",
                title="llama-server bound to 127.0.0.1 only",
                status=ControlStatus.FAIL,
                evidence=f"llama-server appears to listen on public interface: {exposed[0][:120]}",
                remediation="Restart llama-server with --host 127.0.0.1 flag",
                severity="HIGH",
            )

        if any("127.0.0.1" in l for l in lines):
            return ControlResult(
                control_id="HS-003",
                framework="HISPANSHIELD",
                title="llama-server bound to 127.0.0.1 only",
                status=ControlStatus.PASS,
                evidence="llama-server listening on 127.0.0.1 only",
                remediation=None,
                severity="HIGH",
            )

        return ControlResult(
            control_id="HS-003",
            framework="HISPANSHIELD",
            title="llama-server bound to 127.0.0.1 only",
            status=ControlStatus.MANUAL_REVIEW,
            evidence=f"Cannot determine binding from: {lines[0][:120] if lines else 'empty'}",
            remediation="Manually verify llama-server is started with --host 127.0.0.1",
            severity="HIGH",
        )

    def _check_hs004(self) -> ControlResult:
        """HS-004: Elasticsearch bound to 127.0.0.1 (docker inspect or netstat)."""
        # Try docker inspect first
        rc, out, _ = _run(
            "docker inspect elasticsearch 2>/dev/null | "
            "python3 -c \"import sys,json; c=json.load(sys.stdin); "
            "ports=c[0].get('NetworkSettings',{}).get('Ports',{}); print(json.dumps(ports))\" 2>/dev/null"
        )
        if rc == 0 and out:
            try:
                ports = json.loads(out)
                exposed_public: List[str] = []
                for _port, bindings in ports.items():
                    if bindings:
                        for b in bindings:
                            hip = b.get("HostIp", "")
                            if hip not in ("127.0.0.1", "::1", "localhost", ""):
                                exposed_public.append(f"{hip}:{b.get('HostPort')}")
                if exposed_public:
                    return ControlResult(
                        control_id="HS-004",
                        framework="HISPANSHIELD",
                        title="Elasticsearch bound to 127.0.0.1",
                        status=ControlStatus.FAIL,
                        evidence=f"Elasticsearch exposed on: {', '.join(exposed_public)}",
                        remediation=(
                            "In docker-compose.yml set ports: '127.0.0.1:9200:9200' "
                            "instead of '0.0.0.0:9200:9200'"
                        ),
                        severity="CRITICAL",
                    )
                return ControlResult(
                    control_id="HS-004",
                    framework="HISPANSHIELD",
                    title="Elasticsearch bound to 127.0.0.1",
                    status=ControlStatus.PASS,
                    evidence="Elasticsearch container ports bound to 127.0.0.1 only",
                    remediation=None,
                    severity="CRITICAL",
                )
            except (json.JSONDecodeError, IndexError, KeyError):
                pass

        # Fallback: check via ss/netstat for port 9200/9300
        rc2, out2, _ = _run(
            "ss -tlnp 2>/dev/null | grep -E ':920[0-9]|:930[0-9]' || "
            "netstat -tlnp 2>/dev/null | grep -E ':920[0-9]|:930[0-9]'"
        )
        if not out2:
            return ControlResult(
                control_id="HS-004",
                framework="HISPANSHIELD",
                title="Elasticsearch bound to 127.0.0.1",
                status=ControlStatus.NOT_APPLICABLE,
                evidence="Elasticsearch not detected (ports 9200/9300 not listening)",
                remediation=None,
                severity="CRITICAL",
            )

        es_lines = out2.strip().splitlines()
        es_exposed = [
            l for l in es_lines
            if re.search(r"0\.0\.0\.0|::", l)
            and not re.search(r"127\.0\.0\.1", l)
        ]
        if es_exposed:
            return ControlResult(
                control_id="HS-004",
                framework="HISPANSHIELD",
                title="Elasticsearch bound to 127.0.0.1",
                status=ControlStatus.FAIL,
                evidence=f"Elasticsearch listening on public interface: {es_exposed[0][:120]}",
                remediation="Configure Elasticsearch: network.host: 127.0.0.1 in elasticsearch.yml",
                severity="CRITICAL",
            )
        return ControlResult(
            control_id="HS-004",
            framework="HISPANSHIELD",
            title="Elasticsearch bound to 127.0.0.1",
            status=ControlStatus.PASS,
            evidence="Elasticsearch appears bound to loopback only",
            remediation=None,
            severity="CRITICAL",
        )

    def _check_hs005(self) -> ControlResult:
        """HS-005: TPM available (/sys/class/tpm/tpm0 exists)."""
        tpm_path = self.system_root / "sys" / "class" / "tpm" / "tpm0"
        tpm_dev  = self.system_root / "dev" / "tpm0"

        if tpm_path.exists() or tpm_dev.exists():
            evidence = str(tpm_path) if tpm_path.exists() else str(tpm_dev)
            return ControlResult(
                control_id="HS-005",
                framework="HISPANSHIELD",
                title="TPM available",
                status=ControlStatus.PASS,
                evidence=f"TPM device found at {evidence}",
                remediation=None,
                severity="HIGH",
            )

        # Also check /sys/class/tpmrm/tpmrm0 (TPM resource manager)
        tpmrm = self.system_root / "sys" / "class" / "tpmrm" / "tpmrm0"
        if tpmrm.exists():
            return ControlResult(
                control_id="HS-005",
                framework="HISPANSHIELD",
                title="TPM available",
                status=ControlStatus.PASS,
                evidence=f"TPM resource manager found at {tpmrm}",
                remediation=None,
                severity="HIGH",
            )

        return ControlResult(
            control_id="HS-005",
            framework="HISPANSHIELD",
            title="TPM available",
            status=ControlStatus.FAIL,
            evidence="No TPM device found (/sys/class/tpm/tpm0, /dev/tpm0, /sys/class/tpmrm/tpmrm0)",
            remediation=(
                "Ensure TPM 2.0 is enabled in BIOS/UEFI. "
                "If using a VM, enable vTPM. "
                "Install tpm2-tools: apt install tpm2-tools"
            ),
            severity="HIGH",
        )


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------
def _main() -> None:
    parser = argparse.ArgumentParser(
        description="HispanShield GRC Compliance Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "text"],
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Write report to file instead of stdout",
    )
    parser.add_argument(
        "--framework",
        choices=HispanShieldGRCEngine.FRAMEWORKS,
        default=None,
        help="Run only controls for a specific framework",
    )
    parser.add_argument(
        "--system-root",
        default=os.environ.get("HISPANSHIELD_GRC_SYSTEM_ROOT", "/"),
        help="Filesystem root for path checks (default: /)",
    )
    parser.add_argument(
        "--log-dir",
        default=os.environ.get(
            "HISPANSHIELD_GRC_LOG_DIR",
            "/var/log/hispanshield/compliance",
        ),
        help="Directory for compliance artefacts",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    engine = HispanShieldGRCEngine(
        system_root=args.system_root,
        log_dir=args.log_dir,
    )

    if args.framework:
        results = engine.run_framework(args.framework)
    else:
        results = engine.run_all_controls()

    report = engine.generate_report(results, fmt=args.format)
    score  = engine.calculate_score(results)

    if args.output:
        out_path = Path(args.output)
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(report, encoding="utf-8")
            print(
                f"Report written to {out_path}  "
                f"[score: {score['score_pct']}% — "
                f"{score['passed']} PASS / {score['failed']} FAIL]",
                file=sys.stderr,
            )
        except OSError as exc:
            print(f"ERROR writing report: {exc}", file=sys.stderr)
            print(report)
    else:
        print(report)


if __name__ == "__main__":
    _main()
