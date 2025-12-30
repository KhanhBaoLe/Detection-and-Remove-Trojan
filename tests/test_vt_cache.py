import scanner.virustotal_scanner as vt_module
from scanner.virustotal_scanner import VirusTotalScanner


def test_virustotal_cache_hit(monkeypatch, tmp_path):
    calls = {"count": 0}

    # --- fake API call ---
    def fake_query_api(self, file_hash):
        calls["count"] += 1
        return {
            "status": "completed",
            "file_hash": file_hash,
            "is_malicious": False,
            "detection_rate": "0/70",
            "total_engines": 70,
            "trojan_name": None,
            "threat_level": "clean"
        }

    # --- monkeypatch API call ---
    monkeypatch.setattr(
        VirusTotalScanner,
        "_query_by_hash",
        fake_query_api,
        raising=False
    )

    # --- init scanner ---
    scanner = VirusTotalScanner(
        api_key="dummy-key",
        cache_dir=tmp_path  # nếu bạn dùng file cache
    )

    # --- same hash twice ---
    result1 = scanner.scan_hash("abcd1234")
    result2 = scanner.scan_hash("abcd1234")

    assert result1["status"] == "completed"
    assert result2["status"] == "completed"

    # API chỉ được gọi 1 lần
    assert calls["count"] == 1
