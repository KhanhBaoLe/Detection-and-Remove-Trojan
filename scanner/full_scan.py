from scanner.signature_scanner import SignatureScanner
from scanner.behaviour_scanner import BehaviourScanner

class FullScanner:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.sig_scanner = SignatureScanner(db_manager)
        self.beh_scanner = BehaviourScanner(db_manager)
    
    def scan(self, path):
        """Quét toàn diện (signature + behaviour)"""
        files_sig, threats_sig = self.sig_scanner.scan(path)
        files_beh, threats_beh = self.beh_scanner.scan(path)
        
        # Gộp kết quả
        all_threats = self.sig_scanner.threats_found + self.beh_scanner.threats_found
        
        # Loại bỏ trùng lặp
        unique_threats = {t['file_path']: t for t in all_threats}.values()
        
        return max(files_sig, files_beh), len(unique_threats), list(unique_threats)