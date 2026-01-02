import os
from scanner.base_scanner import BaseScanner
from database.models import BehaviourPattern
from utils.file_hash import calculate_file_hash
from config.settings import SCAN_SKIP_DIRS, SIGNATURE_HASH_ALGO


class BehaviourScanner(BaseScanner):
    def __init__(self, db_manager):
        super().__init__(db_manager)
        self.threats_found = []
        self.skip_dirs = set(SCAN_SKIP_DIRS)

    def scan(self, path, scan_id=None):
        """Scan files using behaviour-based detection (Manual String Matching)"""
        self.threats_found = []
        files_scanned = 0

        try:
            patterns = (
                self.db_manager.session
                .query(BehaviourPattern)
                .filter_by(is_active=True)
                .all()
            )
        except:
            patterns = []

        # ---------------------------
        # 1. Gom file cần quét
        # ---------------------------
        if os.path.isfile(path):
            files_to_scan = [path]
        else:
            files_to_scan = []
            ALLOWED_BEHAVIOUR_EXTENSIONS = (
                ".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".msi"
            )
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in self.skip_dirs]
                for file in files:
                    if file.lower().endswith(ALLOWED_BEHAVIOUR_EXTENSIONS):
                        files_to_scan.append(os.path.join(root, file))

        print("\n" + "=" * 70)
        print("🔎 BEHAVIOUR SCANNER (MANUAL MODE)")
        print(f"📂 Files to scan: {len(files_to_scan)}")
        print("=" * 70 + "\n")

        # ---------------------------
        # 2. Quét từng file
        # ---------------------------
        for file_path in files_to_scan:
            files_scanned += 1
            suspicious_score = 0.0
            detected_patterns = []
            file_name = os.path.basename(file_path)

            try:
                # Bỏ qua nếu có trong Whitelist
                file_hash = calculate_file_hash(file_path, algorithm=SIGNATURE_HASH_ALGO)
                if file_hash and self.db_manager.is_whitelisted(file_hash):
                    print(f"[{files_scanned}] ⏩ Whitelisted: {file_name}")
                    continue

                # --- CHECK 1: EICAR ---
                if self.scan_eicar(file_path):
                    self._add_threat(scan_id, file_path, file_hash, "EICAR-Test-File", "high")
                    continue

                # --- CHECK 2: ĐỌC NỘI DUNG ---
                with open(file_path, 'rb') as f:
                    content = f.read(1024 * 1024 * 10) # 10MB Limit
                    content_str = content.decode(errors='ignore')

                # --- CHECK 3: DATABASE PATTERNS ---
                for pattern in patterns:
                    if pattern.pattern_value.lower() in content_str.lower():
                        suspicious_score += pattern.severity_score
                        detected_patterns.append(pattern.pattern_name)

                suspicious_keywords = [
                    # Execution
                    b'eval(', b'exec(', b'system(', b'cmd.exe', b'powershell',
                    # Injection
                    b'VirtualAlloc', b'WriteProcessMemory', b'CreateRemoteThread', b'ReflectiveLoader',
                    # Downloading
                    b'URLDownloadToFile', b'InternetOpenUrl',
                    # Keylogging (MỚI)
                    b'SetWindowsHookEx', b'GetAsyncKeyState', b'GetForegroundWindow',
                    # Persistence/Registry (MỚI)
                    b'RegSetValueEx', b'RegCreateKeyEx',
                    # Stealth
                    b'IsDebuggerPresent', b'ShowWindow'
                ]
                
                for keyword in suspicious_keywords:
                    if keyword in content:
                        suspicious_score += 2.0
                        detected_patterns.append(f"Keyword:{keyword.decode(errors='ignore')}")

                # --- CHECK 5: DETECT PYINSTALLER / PACKER (ĐÃ SỬA) ---
                packer_markers = [
                    b'MEI', b'pyi-windows', b'pyimod01', b'UPX0', b'UPX1'
                ]
                
                if any(m in content for m in packer_markers):
                    suspicious_score += 2.0 
                    detected_patterns.append("Packed/Obfuscated (PyInstaller/UPX)")
                    print(f"    ⚠️ Detected Packer/Obfuscation in {file_name}")

                # Ngưỡng phát hiện: >= 6.0 là Threat
                if suspicious_score >= 6.0:
                    threat_level = 'high' if suspicious_score >= 10.0 else 'medium'
                    trojan_name = f"Heur.Suspicious ({', '.join(detected_patterns[:3])})"
                    
                    self._add_threat(scan_id, file_path, file_hash, trojan_name, threat_level)
                    print(f"[{files_scanned}] 🔴 DETECTED: {file_name} (Score: {suspicious_score})")
                else:
                    # File sạch hoặc điểm thấp
                    pass

            except Exception as e:
                print(f"⚠️ Error: {e}")

        return files_scanned, len(self.threats_found)

    def _add_threat(self, scan_id, file_path, file_hash, name, level):
        """Hàm phụ trợ để lưu threat"""
        detection = {
            'file_path': file_path,
            'file_hash': file_hash,
            'trojan_name': name,
            'threat_level': level,
            'detection_method': 'behaviour_static'
        }
        self.record_detection(scan_id, detection)