import yara
import os
from utils.logger import setup_logger

logger = setup_logger("YaraScanner")

class YaraScanner:
    def __init__(self, rule_path=None):
        self.rules = None
        self._compile_rules(rule_path)

    def _compile_rules(self, rule_path):
        # Sử dụng r""" để Python hiểu đây là chuỗi thô, không xử lý ký tự đặc biệt
        default_rules = r"""
        rule Suspicious_Keywords {
            meta:
                description = "Detects common suspicious strings"
                severity = "Medium"
            strings:
                $s1 = "eval(" nocase
                $s2 = "base64_decode" nocase
                $s3 = "CreateRemoteThread" ascii wide
                $s4 = "VirtualAlloc" ascii wide
                $s5 = "WriteProcessMemory" ascii wide
                $s6 = "cmd.exe /c" nocase
                $s7 = "powershell" nocase
            condition:
                any of them
        }

        rule EICAR_Test_File {
            meta:
                description = "Standard EICAR Test File"
                severity = "Critical"
            strings:
                // Escape dấu \ thành \\ để YARA hiểu đúng
                $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            condition:
                $eicar
        }
        """

        try:
            if rule_path and os.path.exists(rule_path):
                self.rules = yara.compile(filepath=rule_path)
                logger.info(f"Loaded YARA rules from {rule_path}")
            else:
                self.rules = yara.compile(source=default_rules)
                logger.info("Loaded DEFAULT embedded YARA rules")
        except Exception as e:
            logger.error(f"YARA compilation error: {e}")
            self.rules = None

    def scan(self, file_path):
        if not self.rules or not os.path.exists(file_path):
            return []
        try:
            matches = self.rules.match(file_path)
            results = []
            for match in matches:
                results.append({
                    'rule': match.rule,
                    'tags': match.tags,
                    'meta': match.meta
                })
            return results
        except yara.Error as e:
            return []