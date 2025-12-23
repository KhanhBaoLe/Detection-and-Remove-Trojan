import os

from config import settings
from database.db_manager import DatabaseManager
from scanner.behaviour_scanner import BehaviourScanner


def test_behaviour_scanner_flags_high_score(tmp_path, monkeypatch):
    db_path = tmp_path / "behaviour_test.db"
    os.makedirs(db_path.parent, exist_ok=True)
    monkeypatch.setattr(settings, "DATABASE_PATH", str(db_path))

    db_manager = DatabaseManager()
    scanner = BehaviourScanner(db_manager)

    suspicious_file = tmp_path / "suspicious.exe"
    suspicious_file.write_text(
        "WriteProcessMemory\n"
        "http://malicious.example\n"
        "PowerShell -enc AAA\n"
        "VirtualAlloc\n"
        "CreateRemoteThread\n"
        "UPX0"
    )

    files_scanned, threats_found = scanner.scan(str(suspicious_file))

    assert files_scanned == 1
    assert threats_found == 1
    assert scanner.threats_found[0]["threat_level"] in {"high", "critical"}

    db_manager.close()

