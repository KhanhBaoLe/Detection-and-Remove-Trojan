from abc import ABC, abstractmethod
import os
from utils.logger import setup_logger
from pathlib import Path
logger = setup_logger("BaseScanner")


class BaseScanner:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.threats_found = []
    
    def is_suspicious_extension(self, file_path):
        """Kiểm tra file có extension đáng ngờ không"""
        from config.settings import SCAN_EXTENSIONS
        
        try:
            ext = os.path.splitext(file_path)[1].lower()
            return ext in SCAN_EXTENSIONS
        except Exception as e:
            return False
    
    def scan_eicar(self, file_path):
        """Kiểm tra EICAR test string"""
        eicar_string = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        
        try:
            with open(file_path, "rb") as f:
                content = f.read(1024)  # Chỉ đọc 1KB đầu
                return eicar_string in content
        except:
            return False
