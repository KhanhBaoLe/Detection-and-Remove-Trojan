import os
import math
import json
import subprocess
from collections import Counter

import pefile

from utils.logger import setup_logger

logger = setup_logger(__name__)


SUSPICIOUS_APIS = {
    "WriteProcessMemory",
    "CreateRemoteThread",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "VirtualAllocEx",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
}


class PEHeuristicScanner:
    def __init__(self, trusted_signers_path="config/trusted_signers.json"):
        self.trusted_signers = self._load_trusted_signers(trusted_signers_path)

    # ==========================================================
    # PUBLIC API
    # ==========================================================
    def scan(self, file_path: str) -> dict:
        if not os.path.exists(file_path):
            raise FileNotFoundError(file_path)

        score = 0
        reasons = []

        # ---------- LOAD PE ----------
        try:
            pe = pefile.PE(file_path, fast_load=False)
        except Exception as exc:
            logger.warning("Not a valid PE file: %s", exc)
            return self._result(
                score=0,
                level="low",
                reasons=["Not a PE executable"],
            )

        # ---------- ENTROPY ----------
        entropy = self._file_entropy(file_path)
        if entropy > 7.2:
            score += 30
            reasons.append(f"High entropy ({entropy:.2f}) - possible packer")

        # ---------- SECTIONS ----------
        section_findings = self._analyze_sections(pe)
        if section_findings:
            score += 20
            reasons.extend(section_findings)

        # ---------- IMPORTS ----------
        suspicious_imports = self._analyze_imports(pe)
        if suspicious_imports:
            score += min(len(suspicious_imports) * 5, 25)
            reasons.append(
                "Suspicious imports: " + ", ".join(suspicious_imports)
            )

        # ---------- SIGNATURE ----------
        sig_info = self._get_signature_info(file_path)
        if sig_info:
            if sig_info["trusted"]:
                score -= 40
                reasons.append("Trusted digital signature")
            elif sig_info["signed"] and not sig_info["trusted"]:
                score += 15
                reasons.append("Signed but untrusted certificate")
        else:
            score += 10
            reasons.append("Unsigned executable")

        score = max(0, min(score, 100))
        level = self._map_score(score)

        return self._result(
            score=score,
            level=level,
            reasons=reasons,
            extra={
                "entropy": entropy,
                "signed": sig_info["signed"] if sig_info else False,
                "signer": sig_info.get("subject") if sig_info else None,
            },
        )

    # ==========================================================
    # INTERNALS
    # ==========================================================
    def _file_entropy(self, path: str) -> float:
        with open(path, "rb") as f:
            data = f.read()
        if not data:
            return 0.0

        counts = Counter(data)
        entropy = 0.0
        for count in counts.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy

    def _analyze_sections(self, pe):
        findings = []

        for section in pe.sections:
            name = section.Name.decode(errors="ignore").strip("\x00").lower()
            flags = section.Characteristics

            # RWX section
            if (
                flags & 0x20000000  # EXECUTE
                and flags & 0x40000000  # READ
                and flags & 0x80000000  # WRITE
            ):
                findings.append(f"RWX section: {name}")

            if any(x in name for x in ("upx", "aspack", "packed")):
                findings.append(f"Suspicious section name: {name}")

        return findings

    def _analyze_imports(self, pe):
        hits = set()

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return []

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    api = imp.name.decode(errors="ignore")
                    if api in SUSPICIOUS_APIS:
                        hits.add(api)

        return sorted(hits)

    def _get_signature_info(self, file_path):
        if os.name != "nt":
            return None

        try:
            cmd = [
                "powershell",
                "-Command",
                f"Get-AuthenticodeSignature '{file_path}' | ConvertTo-Json",
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )

            if proc.returncode != 0 or not proc.stdout:
                return None

            data = json.loads(proc.stdout)

            status = data.get("Status")
            cert = data.get("SignerCertificate")

            if not cert:
                return {"signed": False, "trusted": False}

            subject = cert.get("Subject", "")
            trusted = any(w in subject for w in self.trusted_signers)

            return {
                "signed": True,
                "trusted": trusted,
                "subject": subject,
                "status": status,
            }

        except Exception as exc:
            logger.warning("Signature check failed: %s", exc)
            return None

    def _load_trusted_signers(self, path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _map_score(self, score):
        if score >= 70:
            return "critical"
        if score >= 40:
            return "high"
        if score >= 20:
            return "medium"
        return "low"

    def _result(self, score, level, reasons, extra=None):
        return {
            "detection_method": "pe_heuristic",
            "score": score,
            "threat_level": level,
            "is_malicious": level in {"high", "critical"},
            "reasons": reasons,
            "details": extra or {},
        }
