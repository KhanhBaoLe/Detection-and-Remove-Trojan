import json
import math
import subprocess
from collections import Counter
from typing import Dict, Iterable, List, Optional, Set, Tuple


def is_pe_file(file_path: str) -> bool:
    """Lightweight PE check using MZ/PE headers to avoid heavy deps."""
    try:
        with open(file_path, "rb") as f:
            mz = f.read(2)
            if mz != b"MZ":
                return False
            f.seek(0x3C)
            offset_bytes = f.read(4)
            if len(offset_bytes) < 4:
                return False
            pe_offset = int.from_bytes(offset_bytes, "little")
            f.seek(pe_offset)
            return f.read(4) == b"PE\x00\x00"
    except Exception:
        return False


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a byte sequence."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def analyze_pe_file(file_path: str) -> Dict:
    """
    Apply lightweight static heuristics for PE files.
    Returns a dict with score, reasons, and raw metrics.
    """
    result = {
        "score": 0.0,
        "reasons": [],  
        "entropy": 0.0,
        "packer_markers": [],
        "suspicious_imports": [],
        "analysis_error": None,
    }

    try:
        with open(file_path, "rb") as f:
            # Read only first 2 MB for entropy/marker checks to stay fast
            blob = f.read(2 * 1024 * 1024)

        entropy = _shannon_entropy(blob)
        result["entropy"] = entropy

        # Entropy heuristic
        if entropy >= 7.2:
            result["score"] += 3.0
            result["reasons"].append(f"High entropy ({entropy:.2f})")

        # Packer/obfuscation markers
        packer_markers = [b"UPX", b"MPRESS", b"ASPACK", b"VMProtect", b"Themida"]
        found_markers = [m.decode("ascii", errors="ignore") for m in packer_markers if m in blob]
        if found_markers:
            result["packer_markers"] = found_markers
            result["score"] += 1.5  
            result["reasons"].append(f"Packer markers: {', '.join(found_markers)}")

        suspicious_imports = [
            # Process Injection / Manipulation
            b"VirtualAlloc", b"VirtualProtect", b"WriteProcessMemory",
            b"CreateRemoteThread", b"OpenProcess", b"ReadProcessMemory",
            b"QueueUserAPC", b"SetThreadContext",
            
            # Execution
            b"WinExec", b"ShellExecute", b"CreateProcess",
            
            # Network / Dropper
            b"URLDownloadToFile", b"InternetOpen", b"InternetConnect",
            
            # Keylogging / Hooking (Đặc trưng Trojan)
            b"SetWindowsHookEx", b"GetAsyncKeyState", b"GetForegroundWindow",
            
            # Persistence / Registry (Đặc trưng Trojan)
            b"RegSetValueEx", b"RegCreateKeyEx",
            
            # Anti-Debug / Stealth
            b"IsDebuggerPresent", b"ShowWindow"
        ]
        
        found_imports: List[str] = []
        lower_blob = blob.lower()
        for imp in suspicious_imports:
            if imp.lower() in lower_blob:
                found_imports.append(imp.decode("ascii", errors="ignore"))

        if found_imports:
            result["suspicious_imports"] = found_imports
            result["score"] += min(2.0 + 0.5 * (len(found_imports) - 1), 6.0)
            result["reasons"].append(f"Suspicious imports: {', '.join(found_imports[:5])}...")

        # Abnormal size (very small PE often suspect)
        try:
            import os

            file_size = os.path.getsize(file_path)
            if file_size < 40 * 1024:  # <40KB often loaders/dropper stubs
                result["score"] += 1.5
                result["reasons"].append(f"Unusually small PE ({file_size} bytes)")
        except Exception:
            pass

    except Exception as exc:
        result["analysis_error"] = str(exc)

    return result


def _match_signer(subject: str, trusted_signers: Iterable[str]) -> Optional[str]:
    subject_lower = subject.lower()
    for signer in trusted_signers:
        if signer and signer.lower() in subject_lower:
            return signer
    return None


def is_trusted_signer(file_path: str, trusted_signers: Set[str]) -> Tuple[bool, Optional[str]]:
    """
    Check Authenticode signer via PowerShell (Windows only).
    Returns (is_trusted, matched_signer).
    """
    try:
        cmd = [
            "powershell",
            "-Command",
            "(Get-AuthenticodeSignature -FilePath '{0}' | "
            "Select-Object Status,SignerCertificate | ConvertTo-Json -Compress)".format(file_path)
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        if proc.returncode != 0 or not proc.stdout:
            return False, None

        data = json.loads(proc.stdout)
        # PowerShell may return an array if piped; handle both
        if isinstance(data, list) and data:
            data = data[0]
        status = str(data.get("Status") or "").lower()
        signer_cert = data.get("SignerCertificate") or {}
        subject = signer_cert.get("Subject") or signer_cert.get("SubjectName") or ""

        if status != "valid" or not subject:
            return False, None

        matched = _match_signer(subject, trusted_signers)
        return (matched is not None), matched
    except Exception:
        return False, None