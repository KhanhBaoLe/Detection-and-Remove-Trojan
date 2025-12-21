import os
import re
from scanner.base_scanner import BaseScanner
from database.models import BehaviourPattern
from utils.file_hash import calculate_file_hash

class BehaviourScanner(BaseScanner):
    def scan(self, path):
        """Quét theo hành vi đáng ngờ"""
        self.threats_found = []
        files_scanned = 0
        
        patterns = self.db_manager.session.query(BehaviourPattern).filter_by(is_active=True).all()
        
        if os.path.isfile(path):
            files_to_scan = [path]
        else:
            files_to_scan = []
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if self.is_suspicious_extension(file_path):
                        files_to_scan.append(file_path)
        
        print(f"\n{'='*70}")
        print(f"🔎 BEHAVIOUR SCANNER")
        print(f"📂 Files to scan: {len(files_to_scan)}")
        print(f"🎯 Active patterns: {len(patterns)}")
        print(f"{'='*70}\n")
        
        for file_path in files_to_scan:
            files_scanned += 1
            suspicious_score = 0
            detected_patterns = []
            
            file_name = os.path.basename(file_path)
            print(f"[{files_scanned}/{len(files_to_scan)}] 📂 Scanning: {file_name}")
            
            try:
                # ===== CHECK 1: EICAR TEST FILE =====
                if self.scan_eicar(file_path):
                    self.threats_found.append({
                        'file_path': file_path,
                        'file_hash': calculate_file_hash(file_path),
                        'trojan_name': "EICAR-Test-File (Behaviour Detection)",
                        'threat_level': 'high',
                        'detection_method': 'behaviour'
                    })
                    print("    🔴 EICAR pattern detected!")
                    continue
                
                # ===== CHECK 2: DATABASE PATTERNS =====
                with open(file_path, 'rb') as f:
                    content = f.read(1024 * 100)  # Đọc 100KB đầu
                    content_str = str(content)
                    
                    print(f"    📄 File size: {len(content)} bytes")
                    
                    for pattern in patterns:
                        if pattern.pattern_value.lower() in content_str.lower():
                            suspicious_score += pattern.severity_score
                            detected_patterns.append(pattern.pattern_name)
                            print(f"    ⚠️ Pattern found: {pattern.pattern_name} (+{pattern.severity_score})")
                
                # ===== CHECK 3: SUSPICIOUS KEYWORDS =====
                suspicious_keywords = [
                    b'eval(', b'exec(', b'shell_exec', b'system(',
                    b'cmd.exe', b'powershell', b'download',
                    b'http://', b'https://',
                    b'CreateProcess', b'VirtualAlloc',
                    b'WriteProcessMemory', b'CreateRemoteThread'
                ]
                
                for keyword in suspicious_keywords:
                    if keyword in content:
                        suspicious_score += 1.5
                        detected_patterns.append(f"Keyword: {keyword.decode('utf-8', errors='ignore')}")
                        print(f"    ⚠️ Suspicious keyword: {keyword.decode('utf-8', errors='ignore')} (+1.5)")
                
                # ===== VERDICT =====
                if suspicious_score >= 7.0:
                    threat_level = 'critical' if suspicious_score >= 9 else 'high' if suspicious_score >= 7 else 'medium'
                    self.threats_found.append({
                        'file_path': file_path,
                        'file_hash': calculate_file_hash(file_path),
                        'trojan_name': f"Suspicious.Behaviour ({', '.join(detected_patterns[:3])}...)",
                        'threat_level': threat_level,
                        'detection_method': 'behaviour'
                    })
                    print(f"    🔴 THREAT DETECTED! Score: {suspicious_score:.1f} - Level: {threat_level.upper()}")
                else:
                    print(f"    ✅ Clean (Score: {suspicious_score:.1f})")
                    
            except Exception as e:
                print(f"    ⚠️ Error scanning file: {str(e)}")
        
        print(f"\n{'='*70}")
        print(f"📊 BEHAVIOUR SCAN SUMMARY")
        print(f"{'='*70}")
        print(f"✅ Files Scanned: {files_scanned}")
        print(f"🔴 Threats Found: {len(self.threats_found)}")
        print(f"{'='*70}\n")
        
        return files_scanned, len(self.threats_found)