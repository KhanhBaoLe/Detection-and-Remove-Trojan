import hashlib
import os
from datetime import datetime
from typing import Optional


def _get_hasher(algorithm: str):
    algo = algorithm.lower()
    if algo == "md5":
        return hashlib.md5()
    if algo == "sha1":
        return hashlib.sha1()
    if algo == "sha256":
        return hashlib.sha256()
    raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def calculate_file_hash(file_path: str, algorithm: str = "sha256") -> Optional[str]:
    """
    Calculate file hash with configurable algorithm.

    Args:
        file_path: path to file
        algorithm: md5 | sha1 | sha256 (default)
    """
    try:
        hasher = _get_hasher(algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None


def get_file_info(file_path):
    """Lấy thông tin file"""
    try:
        stat = os.stat(file_path)
        return {
            'size': stat.st_size,
            'created': datetime.fromtimestamp(stat.st_ctime),
            'modified': datetime.fromtimestamp(stat.st_mtime)
        }
    except:
        return None