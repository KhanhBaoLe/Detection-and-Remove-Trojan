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
        
        for file_path in files_to_scan:
            files_scanned += 1
            suspicious_score = 0
            detected_patterns = []
            
            try:
                with open(file_path, 'rb') as f:
                    content = f.read(1024 * 100)  # Đọc 100KB đầu
                    content_str = str(content)
                    
                    for pattern in patterns:
                        if pattern.pattern_value.lower() in content_str.lower():
                            suspicious_score += pattern.severity_score
                            detected_patterns.append(pattern.pattern_name)
                
                # Nếu điểm nghi ngờ cao, thêm vào threats
                if suspicious_score >= 7.0:
                    threat_level = 'critical' if suspicious_score >= 9 else 'high' if suspicious_score >= 7 else 'medium'
                    self.threats_found.append({
                        'file_path': file_path,
                        'file_hash': calculate_file_hash(file_path),
                        'trojan_name': f"Suspicious.Behaviour ({', '.join(detected_patterns)})",
                        'threat_level': threat_level,
                        'detection_method': 'behaviour'
                    })
            except:
                pass
        
        return files_scanned, len(self.threats_found)