import sys
import os

def get_base_dir():
    # Khi chạy bằng PyInstaller
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    # Khi chạy bằng Python bình thường
    return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = get_base_dir()
sys.path.insert(0, BASE_DIR)

from gui.main_window import TrojanScannerGUI


def main():
    app = TrojanScannerGUI()
    app.run()


if __name__ == "__main__":
    main()