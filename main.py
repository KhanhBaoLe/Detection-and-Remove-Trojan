import sys
import os

# Add project root to path để import được các module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.main_window import TrojanScannerGUI

if __name__ == "__main__":
    import sys
    import os
    
    # Add project root to path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    app = TrojanScannerGUI()
    app.run()