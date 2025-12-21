from abc import ABC, abstractmethod
import os

class BaseScanner(ABC):
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.threats_found = []
    
    @abstractmethod
    def scan(self, path):
        pass
    
    def is_suspicious_extension(self, file_path):
        from config.settings import SCAN_EXTENSIONS
        ext = os.path.splitext(file_path)[1].lower()
        return ext in SCAN_EXTENSIONS
    def scan_eicar(self, file_path):
        try:
            with open(file_path, "rb") as f:
                data = f.read()
                if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in data:
                    return True
        except:
            pass
        return False