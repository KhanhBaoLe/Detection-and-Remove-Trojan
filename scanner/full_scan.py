from scanner.signature_scanner import SignatureScanner
from scanner.behaviour_scanner import BehaviourScanner


class FullScanner:
    """
    FullScanner:
    - Kết hợp Signature Scan + Behaviour Scan
    - KHÔNG thực hiện Dynamic Analysis
    - Dynamic analysis phải chạy riêng (on-demand)
    """

    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.sig_scanner = SignatureScanner(db_manager)
        self.beh_scanner = BehaviourScanner(db_manager)

    def scan(self, path):
        """
        Thực hiện full scan (static + behaviour)

        Args:
            path (str): thư mục cần quét

        Returns:
            tuple:
                files_scanned (int)
                threats_count (int)
                threats_list (list)
        """

        # ===== 1. SIGNATURE SCAN =====
        files_sig, _ = self.sig_scanner.scan(path)

        # ===== 2. BEHAVIOUR SCAN =====
        files_beh, _ = self.beh_scanner.scan(path)

        # ===== 3. MERGE THREATS =====
        all_threats = (
            self.sig_scanner.threats_found +
            self.beh_scanner.threats_found
        )

        # Loại bỏ trùng theo file_path
        unique_threats = {
            threat['file_path']: threat
            for threat in all_threats
        }

        unique_threats_list = list(unique_threats.values())

        # ===== 4. RETURN =====
        return (
            max(files_sig, files_beh),
            len(unique_threats_list),
            unique_threats_list
        )
