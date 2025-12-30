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
SIGNATURE_HASH_ALGO = 'md5'  # match local signature database format
PE_HEURISTIC_MIN_SCORE = 6.0
PE_TRUSTED_SIGNER_MAX_SCORE = 3.5  # trusted signers bypass if heuristics below this
TRUSTED_SIGNERS = {
    "Microsoft Corporation",
    "Microsoft Windows",
    "Google LLC",
    "Adobe Systems",
    "Apple Inc",
    "NVIDIA Corporation",
}

# DYNAMIC ANALYSIS SETTINGS
DYNAMIC_ANALYSIS_ENABLED = True
DYNAMIC_TIMEOUT_SECONDS = 30
DYNAMIC_MONITOR_DIR = os.path.join(BASE_DIR, 'dynamic_analysis', 'monitors')
DYNAMIC_SAMPLES_DIR = os.path.join(BASE_DIR, 'dynamic_analysis', 'samples')
DYNAMIC_SANDBOX_DIR = os.path.join(BASE_DIR, 'temp', 'dynamic_sandbox')
DYNAMIC_ENABLE_NETWORK = False  # Tắt mạng vì an toàn
DYNAMIC_FIREWALL_GUARD_ENABLED = True  # Cho phép chặn mạng bằng firewall khi disable network

# Tạo thư mục nếu chưa có
for directory in [
    os.path.dirname(DATABASE_PATH),
    QUARANTINE_DIR,
    LOG_DIR,
    SIGNATURE_DIR,
    DYNAMIC_SANDBOX_DIR,
    DYNAMIC_MONITOR_DIR,
    DYNAMIC_SAMPLES_DIR
]:
    os.makedirs(directory, exist_ok=True)

THREAT_LEVELS = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4
}

SCAN_EXTENSIONS = ['.exe', '.dll', '.bat', '.cmd', '.vbs', '.js', '.jar', '.msi']

# Directories skipped during traversal
SCAN_SKIP_DIRS = {
    '.git', '__pycache__', 'build', 'dist',
    '.venv', 'venv', 'node_modules'
}