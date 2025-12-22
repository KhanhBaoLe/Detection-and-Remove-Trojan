import os
import sys

# =========================
# Base directory
# =========================
def get_base_dir():
    # Khi chạy bằng PyInstaller
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    # Khi chạy Python bình thường
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BASE_DIR = get_base_dir()

# =========================
# Paths
# =========================
DATABASE_PATH = os.path.join(BASE_DIR, 'database', 'scanner.db')
QUARANTINE_DIR = os.path.join(BASE_DIR, 'quarantine', 'quarantined')
LOG_DIR = os.path.join(BASE_DIR, 'logs')
SIGNATURE_DIR = os.path.join(BASE_DIR, 'signatures')
CONFIG_DIR = os.path.join(BASE_DIR, 'config')

SCAN_EXTENSIONS_FILE = os.path.join(CONFIG_DIR, 'scan_extensions.txt')

# =========================
# Create directories if missing
# =========================
for directory in [
    os.path.dirname(DATABASE_PATH),
    QUARANTINE_DIR,
    LOG_DIR,
    SIGNATURE_DIR,
    CONFIG_DIR
]:
    os.makedirs(directory, exist_ok=True)

# =========================
# Threat levels
# =========================
THREAT_LEVELS = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4
}

# =========================
# Scan extensions (dynamic)
# =========================
DEFAULT_SCAN_EXTENSIONS = [
    '.exe', '.dll', '.bat', '.cmd',
    '.vbs', '.js', '.jar', '.msi'
]

def load_scan_extensions():
    """
    Load scan extensions from file.
    If file not exists or empty → use default.
    """
    if os.path.exists(SCAN_EXTENSIONS_FILE):
        with open(SCAN_EXTENSIONS_FILE, 'r', encoding='utf-8') as f:
            exts = [
                line.strip().lower()
                for line in f
                if line.strip().startswith('.')
            ]
            if exts:
                return exts
    return DEFAULT_SCAN_EXTENSIONS.copy()

def save_scan_extensions(exts):
    """
    Save scan extensions to config file.
    """
    with open(SCAN_EXTENSIONS_FILE, 'w', encoding='utf-8') as f:
        for ext in sorted(set(exts)):
            f.write(ext.lower() + '\n')
