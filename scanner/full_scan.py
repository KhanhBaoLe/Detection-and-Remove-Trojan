from scanner.signature_scanner import SignatureScanner
from scanner.behaviour_scanner import BehaviourScanner
from utils.logger import setup_logger

logger = setup_logger("FullScanner")


class FullScanner:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.sig_scanner = SignatureScanner(db_manager)
        self.beh_scanner = BehaviourScanner(db_manager)

    def scan(self, path):
        """Quét toàn diện (signature + behaviour)"""
        logger.info(f"Start full scan: {path}")

        try:
            files_sig, threats_sig = self.sig_scanner.scan(path)
            files_beh, threats_beh = self.beh_scanner.scan(path)

            # Gộp kết quả
            all_threats = (
                self.sig_scanner.threats_found +
                self.beh_scanner.threats_found
            )

            # Loại bỏ trùng lặp theo file_path
            unique_threats = {
                threat['file_path']: threat
                for threat in all_threats
            }.values()

            logger.info(
                f"Full scan completed | "
                f"files={max(files_sig, files_beh)} | "
                f"threats={len(unique_threats)}"
            )

            return max(files_sig, files_beh), len(unique_threats), list(unique_threats)

        except Exception:
            logger.exception("Full scan failed")
            raise
