import os
from scanner.base_scanner import BaseScanner
from utils.file_hash import calculate_file_hash
from utils.logger import setup_logger

logger = setup_logger("SignatureScanner")


class SignatureScanner(BaseScanner):
    def scan(self, path):
        """Quét theo signature (hash)"""
        logger.info(f"Start signature scan: {path}")

        self.threats_found = []
        files_scanned = 0

        try:
            # Xác định danh sách file cần scan
            if os.path.isfile(path):
                files_to_scan = [path]
            else:
                files_to_scan = []
                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if self.is_suspicious_extension(file_path):
                            files_to_scan.append(file_path)

            logger.info(f"Total files to scan (signature): {len(files_to_scan)}")

            # Scan từng file
            for file_path in files_to_scan:
                files_scanned += 1

                try:
                    file_hash = calculate_file_hash(file_path)
                    if not file_hash:
                        logger.warning(f"Cannot calculate hash: {file_path}")
                        continue

                    # EICAR test
                    if self.scan_eicar(file_path):
                        logger.warning(f"EICAR test file detected: {file_path}")
                        self.threats_found.append({
                            'file_path': file_path,
                            'file_hash': 'EICAR_TEST',
                            'trojan_name': 'EICAR-Test-File',
                            'threat_level': 'high',
                            'detection_method': 'signature'
                        })
                        continue

                    # Kiểm tra whitelist
                    if self.db_manager.is_whitelisted(file_hash):
                        logger.info(f"Whitelisted file skipped: {file_path}")
                        continue

                    # Kiểm tra signature DB
                    signature = self.db_manager.check_signature(file_hash)
                    if signature:
                        logger.info(
                            f"Threat detected | {file_path} | {signature.trojan_name}"
                        )
                        self.threats_found.append({
                            'file_path': file_path,
                            'file_hash': file_hash,
                            'trojan_name': signature.trojan_name,
                            'threat_level': signature.threat_level,
                            'detection_method': 'signature'
                        })

                except Exception:
                    # Lỗi từng file → log nhưng không dừng scan
                    logger.exception(f"Error scanning file: {file_path}")

            logger.info(
                f"Signature scan completed | files_scanned={files_scanned} | threats={len(self.threats_found)}"
            )
            return files_scanned, len(self.threats_found)

        except Exception:
            # Lỗi nghiêm trọng → log + throw lại cho GUI
            logger.exception("Signature scan failed")
            raise
