import tempfile
import os
import sys
import pytest
from scanner.base_scanner import BaseScanner


class DummyScanner(BaseScanner):
    def scan(self, path):
        pass


@pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="Windows Defender blocks EICAR test string"
)
def test_eicar_detection():
    eicar_string = (
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
        "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )

    fd, tmp_path = tempfile.mkstemp()
    with os.fdopen(fd, "w") as f:
        f.write(eicar_string)

    scanner = DummyScanner(db_manager=None)

    detected = scanner.scan_eicar(tmp_path)

    assert detected is True

    os.remove(tmp_path)
