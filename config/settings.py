import os
import sys

def get_base_dir():
    # Khi chạy bằng PyInstaller
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    # Khi chạy bằng Python bình thường
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BASE_DIR = get_base_dir()

DATABASE_PATH = os.path.join(BASE_DIR, 'database', 'scanner.db')
QUARANTINE_DIR = os.path.join(BASE_DIR, 'quarantine', 'quarantined')
LOG_DIR = os.path.join(BASE_DIR, 'logs')
SIGNATURE_DIR = os.path.join(BASE_DIR, 'signatures')

# Tạo thư mục nếu chưa có
for directory in [
    os.path.dirname(DATABASE_PATH),
    QUARANTINE_DIR,
    LOG_DIR,
    SIGNATURE_DIR
]:
    os.makedirs(directory, exist_ok=True)

THREAT_LEVELS = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4
}

SCAN_EXTENSIONS = ['.exe', '.dll', '.bat', '.cmd', '.vbs', '.js', '.jar', '.msi']
