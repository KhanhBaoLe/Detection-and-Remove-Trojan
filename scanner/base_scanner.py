from abc import ABC, abstractmethod
import os
from pathlib import Path
from utils.logger import setup_logger
from config.settings import SCAN_SKIP_DIRS
logger = setup_logger("BaseScanner")


class BaseScanner:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.threats_found = []
        self.skip_dirs = set(SCAN_SKIP_DIRS)
    
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

    def record_detection(self, scan_id, detection):
        """Persist detection to DB if available and mirror to logger."""
        self.threats_found.append(detection)
        try:
            if self.db_manager:
                self.db_manager.add_detection(
                    scan_id=scan_id,
                    file_path=detection.get('file_path'),
                    file_hash=detection.get('file_hash'),
                    trojan_name=detection.get('trojan_name'),
                    detection_method=detection.get('detection_method'),
                    threat_level=detection.get('threat_level')
                )
        except Exception as exc:
            logger.warning("Failed to persist detection: %s", exc)
        logger.warning(
            "Detection %s | %s | level=%s",
            detection.get('detection_method'),
            detection.get('trojan_name'),
            detection.get('threat_level')
        )
