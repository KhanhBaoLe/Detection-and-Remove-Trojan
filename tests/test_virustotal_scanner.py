from scanner import virustotal_scanner
from scanner.virustotal_scanner import VirusTotalScanner
from utils.file_hash import calculate_file_hash


class DummyResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def test_parse_scan_result_builds_summary():
    scanner = VirusTotalScanner("dummy-key")

    fake_payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "harmless": 5,
                    "undetected": 2,
                },
                "last_analysis_results": {
                    "EngineA": {"category": "malicious", "result": "W32.Test"},
                    "EngineB": {"category": "suspicious", "result": "W32.Test"},
                    "EngineC": {"category": "harmless", "result": None},
                },
            }
        }
    }

    result = scanner._parse_scan_result(fake_payload, "sample.exe", "abcd1234")

    assert result["threat_level"] == "critical"
    assert result["is_malicious"] is True
    assert result["detection_method"] == "virustotal"
    assert result["trojan_name"] == "W32.Test"
    assert result["detection_rate"] == "2/10"


def test_scan_file_by_hash_not_found(monkeypatch, tmp_path):
    sample = tmp_path / "clean.exe"
    sample.write_text("benign sample")

    scanner = VirusTotalScanner("dummy-key")
    monkeypatch.setattr(scanner, "_rate_limit", lambda: None)
    monkeypatch.setattr(
        virustotal_scanner.requests,
        "get",
        lambda *args, **kwargs: DummyResponse(404),
    )

    result = scanner.scan_file_by_hash(str(sample))

    assert result["status"] == "not_found"
    assert (
        result["file_hash"]
        == calculate_file_hash(str(sample), algorithm="sha256")
    )

