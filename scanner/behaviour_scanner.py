import os
from scanner.base_scanner import BaseScanner
from database.models import BehaviourPattern
from utils.file_hash import calculate_file_hash
from config.settings import SCAN_SKIP_DIRS, SIGNATURE_HASH_ALGO


class BehaviourScanner(BaseScanner):
    def __init__(self, db_manager):
        super().__init__(db_manager)

        self.threats_found = []

        # ✅ Skip unnecessary folders (same as SignatureScanner)
        self.skip_dirs = set(SCAN_SKIP_DIRS)

    def scan(self, path, scan_id=None):
        """Scan files using behaviour-based detection"""
        self.threats_found = []
        files_scanned = 0

        patterns = (
            self.db_manager.session
            .query(BehaviourPattern)
            .filter_by(is_active=True)
            .all()
        )

        # ---------------------------
        # Collect files to scan
        # ---------------------------
        if os.path.isfile(path):
            files_to_scan = [path]
        else:
            files_to_scan = []
            for root, dirs, files in os.walk(path):
                # ✅ Skip unwanted directories
                dirs[:] = [d for d in dirs if d not in self.skip_dirs]

                for file in files:
                    file_path = os.path.join(root, file)
                    if self.is_suspicious_extension(file_path):
                        files_to_scan.append(file_path)

        # ---------------------------
        # Header
        # ---------------------------
        print("\n" + "=" * 70)
        print("🔎 BEHAVIOUR SCANNER")
        print(f"📂 Files to scan: {len(files_to_scan)}")
        print(f"🎯 Active patterns: {len(patterns)}")
        print("=" * 70 + "\n")

        # ---------------------------
        # Scan each file
        # ---------------------------
        for file_path in files_to_scan:
            files_scanned += 1
            suspicious_score = 0.0
            detected_patterns = []

            file_name = os.path.basename(file_path)
            print(f"[{files_scanned}/{len(files_to_scan)}] 📂 Scanning: {file_name}")

            try:
                file_hash = calculate_file_hash(file_path, algorithm=SIGNATURE_HASH_ALGO)
                if file_hash and self.db_manager.is_whitelisted(file_hash):
                    print("    ✅ File in whitelist, skipping behaviour scan...")
                    continue

                # ===== CHECK 1: EICAR TEST FILE =====
                if self.scan_eicar(file_path):
                    print("    🔴 EICAR pattern detected!")
                    self.record_detection(scan_id, {
                        'file_path': file_path,
                        'file_hash': file_hash or calculate_file_hash(file_path),
                        'trojan_name': "EICAR-Test-File (Behaviour Detection)",
                        'threat_level': 'high',
                        'detection_method': 'behaviour'
                    })
                    continue

                # ===== READ FILE CONTENT (100KB) =====
                with open(file_path, 'rb') as f:
                    content = f.read(1024 * 100)  # Read first 100KB
                    content_str = content.decode(errors='ignore')

                print(f"    📄 Read size: {len(content)} bytes")

                # ===== CHECK 2: DATABASE BEHAVIOUR PATTERNS =====
                for pattern in patterns:
                    if pattern.pattern_value.lower() in content_str.lower():
                        suspicious_score += pattern.severity_score
                        detected_patterns.append(pattern.pattern_name)
                        print(
                            f"    ⚠️ Pattern found: {pattern.pattern_name} "
                            f"(+{pattern.severity_score})"
                        )

                # ===== CHECK 3: SUSPICIOUS KEYWORDS =====
                suspicious_keywords = [
                    b'eval(', b'exec(', b'shell_exec', b'system(',
                    b'cmd.exe', b'powershell', b'download',
                    b'http://', b'https://',
                    b'CreateProcess', b'VirtualAlloc',
                    b'WriteProcessMemory', b'CreateRemoteThread',
                    b'Base64Decode', b'PowerShell -enc', b'WScript.Shell',
                    b'Registry::SetValue', b'WinExec', b'GetAsyncKeyState',
                    b'Add-MpPreference', b'Invoke-WebRequest', b'AutoIt3.exe',
                    b'Schtasks', b'RunDll32'
                ]

                for keyword in suspicious_keywords:
                    if keyword in content:
                        suspicious_score += 1.5
                        keyword_str = keyword.decode('utf-8', errors='ignore')
                        detected_patterns.append(f"Keyword: {keyword_str}")
                        print(f"    ⚠️ Suspicious keyword: {keyword_str} (+1.5)")

                # ===== CHECK 4: PACKER / OBFUSCATION HINTS =====
                packer_markers = [b'UPX0', b'UPX1', b'MPRESS', b'ASPACK']
                if any(marker in content for marker in packer_markers):
                    suspicious_score += 2.0
                    detected_patterns.append("PackerMarker")
                    print("    ⚠️ Packer marker detected (+2.0)")

                # ===== VERDICT =====
                if suspicious_score >= 7.0:
                    if suspicious_score >= 9.0:
                        threat_level = 'critical'
                    elif suspicious_score >= 7.0:
                        threat_level = 'high'
                    else:
                        threat_level = 'medium'

                    self.threats_found.append({
                        'file_path': file_path,
                        'file_hash': calculate_file_hash(file_path),
                        'trojan_name': (
                            "Suspicious.Behaviour "
                            f"({', '.join(detected_patterns[:3])}...)"
                        ),
                        'threat_level': threat_level,
                        'detection_method': 'behaviour'
                    })

                    print(
                        f"    🔴 THREAT DETECTED! "
                        f"Score: {suspicious_score:.1f} "
                        f"- Level: {threat_level.upper()}"
                    )
                else:
                    print(f"    ✅ Clean (Score: {suspicious_score:.1f})")

            except Exception as e:
                print(f"    ⚠️ Error scanning file: {str(e)}")

        # ---------------------------
        # Summary
        # ---------------------------
        print("\n" + "=" * 70)
        print("📊 BEHAVIOUR SCAN SUMMARY")
        print("=" * 70)
        print(f"✅ Files Scanned: {files_scanned}")
        print(f"🔴 Threats Found: {len(self.threats_found)}")
        print("=" * 70 + "\n")

        return files_scanned, len(self.threats_found)
