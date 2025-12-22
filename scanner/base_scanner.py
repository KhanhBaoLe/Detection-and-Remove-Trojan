from abc import ABC, abstractmethod
import os
from utils.logger import setup_logger
from pathlib import Path
logger = setup_logger("BaseScanner")


class BaseScanner(ABC):
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.threats_found = []

    @abstractmethod
    def scan(self, path):
        pass

    def is_suspicious_extension(self, file_path):
        """
        Kiểm tra extension dựa trên cấu hình động (scan_extensions.txt)
        """
        try:
            from config.settings import load_scan_extensions

            ext = os.path.splitext(file_path)[1].lower()
            allowed_exts = load_scan_extensions()

            return ext in allowed_exts

        except Exception:
            logger.exception(f"Failed to check file extension: {file_path}")
            return False

    def scan_eicar(self, file_path):
        try:
            data = Path(file_path).read_bytes()
            return b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in data
        except Exception:
            logger.exception(f"Failed to scan EICAR file: {file_path}")
            return False
