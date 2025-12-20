import os
from scanner.base_scanner import BaseScanner
from utils.file_hash import calculate_file_hash
# from database.models import BehaviourPattern

class SignatureScanner(BaseScanner):
    def scan(self, path):
        """Quét theo signature (hash)"""
        self.threats_found = []
        files_scanned = 0
        
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
            file_hash = calculate_file_hash(file_path)
            
            if file_hash:
                if self.scan_eicar(file_path):
                    self.threats_found.append({
                        'file_path': file_path,
                        'file_hash': 'EICAR_TEST',
                        'trojan_name': 'EICAR-Test-File',
                        'threat_level': 'high',
                        'detection_method': 'signature'
                    })
                    continue
                # Kiểm tra whitelist
                if self.db_manager.is_whitelisted(file_hash):
                    continue
                
                # Kiểm tra signature
                signature = self.db_manager.check_signature(file_hash)
                if signature:
                    self.threats_found.append({
                        'file_path': file_path,
                        'file_hash': file_hash,
                        'trojan_name': signature.trojan_name,
                        'threat_level': signature.threat_level,
                        'detection_method': 'signature'
                    })
        
        return files_scanned, len(self.threats_found)