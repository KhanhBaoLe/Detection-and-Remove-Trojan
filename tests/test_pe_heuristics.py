from scanner.pe_heuristic_scanner import PEHeuristicScanner


def test_pe_heuristic_flags_suspicious(monkeypatch):
    def fake_analyze_pe(_):
        return {
            "score": 8.2,
            "reasons": ["high_entropy", "packed_sections"]
        }

    monkeypatch.setattr("utils.pe_utils.analyze_pe_file", fake_analyze_pe)
    monkeypatch.setattr("os.path.exists", lambda _: True)
    monkeypatch.setattr(
        "scanner.pe_heuristic_scanner.pefile.PE",
        lambda *args, **kwargs: object()
    )

    scanner = PEHeuristicScanner()
    result = scanner.scan("fake.exe")

    assert result["suspicious"] is True
    assert result["score"] == 8.2
    assert "high_entropy" in result["reasons"]


def test_pe_heuristic_clean_file(monkeypatch):
    def fake_analyze_pe(_):
        return {
            "score": 2.0,
            "reasons": []
        }

    monkeypatch.setattr("utils.pe_utils.analyze_pe_file", fake_analyze_pe)
    monkeypatch.setattr("os.path.exists", lambda _: True)
    monkeypatch.setattr(
        "scanner.pe_heuristic_scanner.pefile.PE",
        lambda *args, **kwargs: object()
    )

    scanner = PEHeuristicScanner()
    result = scanner.scan("clean.exe")

    assert result["suspicious"] is False
    assert result["score"] < 5
