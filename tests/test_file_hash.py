import os
import tempfile
from utils.file_hash import calculate_file_hash


def test_calculate_file_hash_valid_file():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"hello world")
        tmp_path = tmp.name

    sha_hash = calculate_file_hash(tmp_path)
    md5_hash = calculate_file_hash(tmp_path, algorithm="md5")

    assert sha_hash is not None
    assert len(sha_hash) == 64  # SHA-256

    assert md5_hash is not None
    assert len(md5_hash) == 32  # MD5

    os.remove(tmp_path)


def test_calculate_file_hash_nonexistent_file():
    file_hash = calculate_file_hash("not_exist_file.exe")
    assert file_hash is None
