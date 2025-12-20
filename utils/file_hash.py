import hashlib
import os
from datetime import datetime

def calculate_file_hash(file_path, algorithm='md5'):
    """Tính hash của file"""
    try:
        hash_obj = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
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