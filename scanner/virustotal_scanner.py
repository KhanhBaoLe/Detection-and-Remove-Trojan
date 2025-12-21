import requests
import hashlib
import time
import json
import os
from utils.file_hash import calculate_file_hash
from config.api_keys import VIRUSTOTAL_API_KEY

class VirusTotalScanner:
    """
    Scanner tích hợp VirusTotal API
    
    Workflow:
    1. Tính hash của file (SHA256)
    2. Gửi hash đến VirusTotal
    3. Nhận kết quả phân tích từ 70+ antivirus engines
    4. Trả về threat level và thông tin chi tiết
    """
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        self.last_request_time = 0
        self.min_request_interval = 15  # 4 requests/minute = 15s/request
    
    def _rate_limit(self):
        """Đảm bảo không vượt quá giới hạn API (4 requests/minute)"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            print(f"⏳ Rate limiting: waiting {sleep_time:.1f}s...")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def scan_file_by_hash(self, file_path):
        """
        Scan file bằng cách gửi hash (SHA256) đến VirusTotal
        
        Args:
            file_path: Đường dẫn file cần scan
            
        Returns:
            dict: Kết quả phân tích hoặc None nếu lỗi
        """
        try:
            # Tính SHA256 hash
            file_hash = calculate_file_hash(file_path, algorithm='sha256')
            if not file_hash:
                return None
            
            print(f"🔍 Checking hash: {file_hash}")
            
            # Rate limiting
            self._rate_limit()
            
            # Gửi request đến VirusTotal
            url = f"{self.base_url}/files/{file_hash}"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_scan_result(data, file_path, file_hash)
            
            elif response.status_code == 404:
                # Hash không tồn tại trong database của VirusTotal
                print("⚠️ File chưa được scan trên VirusTotal")
                return {
                    'status': 'not_found',
                    'file_path': file_path,
                    'file_hash': file_hash,
                    'message': 'File not found in VirusTotal database'
                }
            
            else:
                print(f"❌ API Error: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ Scan error: {str(e)}")
            return None
    
    def upload_and_scan(self, file_path):
        """
        Upload file lên VirusTotal để scan (file < 32MB)
        
        Args:
            file_path: Đường dẫn file cần scan
            
        Returns:
            dict: Kết quả phân tích hoặc None nếu lỗi
        """
        try:
            import os
            file_size = os.path.getsize(file_path)
            
            # Kiểm tra kích thước file
            if file_size > 32 * 1024 * 1024:  # 32MB
                print("❌ File quá lớn (>32MB) cho free API")
                return None
            
            print(f"📤 Uploading file: {os.path.basename(file_path)} ({file_size} bytes)")
            
            # Rate limiting
            self._rate_limit()
            
            # Upload file
            url = f"{self.base_url}/files"
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = requests.post(url, headers=self.headers, files=files, timeout=60)
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data['data']['id']
                
                print(f"✅ Upload thành công! Analysis ID: {analysis_id}")
                print("⏳ Đợi VirusTotal phân tích...")
                
                # Đợi kết quả (thường mất 10-30s)
                return self._wait_for_analysis(analysis_id, file_path)
            
            else:
                print(f"❌ Upload failed: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ Upload error: {str(e)}")
            return None
    
    def _wait_for_analysis(self, analysis_id, file_path, max_wait=60):
        """
        Đợi VirusTotal hoàn thành phân tích
        
        Args:
            analysis_id: ID của analysis
            file_path: Đường dẫn file
            max_wait: Thời gian đợi tối đa (giây)
            
        Returns:
            dict: Kết quả phân tích
        """
        url = f"{self.base_url}/analyses/{analysis_id}"
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            # Rate limiting
            self._rate_limit()
            
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                status = data['data']['attributes']['status']
                
                if status == 'completed':
                    print("✅ Phân tích hoàn tất!")
                    
                    # Lấy kết quả chi tiết
                    file_hash = data['data']['attributes']['sha256']
                    return self.scan_file_by_hash_direct(file_hash, file_path)
                
                elif status == 'queued':
                    print("⏳ Đang xếp hàng...")
                    time.sleep(5)
                
                else:
                    print(f"⏳ Đang phân tích... ({status})")
                    time.sleep(5)
            
            else:
                break
        
        print("⚠️ Timeout: Không nhận được kết quả")
        return None
    
    def scan_file_by_hash_direct(self, file_hash, file_path):
        """Helper method để lấy kết quả từ hash đã biết"""
        try:
            self._rate_limit()
            url = f"{self.base_url}/files/{file_hash}"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_scan_result(data, file_path, file_hash)
            
            return None
            
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            return None
    
    def _parse_scan_result(self, data, file_path, file_hash):
        """
        Phân tích kết quả từ VirusTotal
        
        Returns:
            dict: Kết quả đã được phân tích
        """
        try:
            attributes = data['data']['attributes']
            stats = attributes['last_analysis_stats']
            results = attributes['last_analysis_results']
            
            # Số engine phát hiện malicious
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total_engines = sum(stats.values())
            
            # Xác định threat level
            detection_rate = (malicious + suspicious) / total_engines if total_engines > 0 else 0
            
            if detection_rate >= 0.3:  # >= 30% engines phát hiện
                threat_level = 'critical'
            elif detection_rate >= 0.1:  # >= 10%
                threat_level = 'high'
            elif suspicious > 0:
                threat_level = 'medium'
            else:
                threat_level = 'low'
            
            # Lấy tên malware từ các engines phát hiện
            detected_names = []
            for engine, result in results.items():
                if result['category'] in ['malicious', 'suspicious']:
                    if result.get('result'):
                        detected_names.append(result['result'])
            
            # Lấy tên phổ biến nhất
            trojan_name = "Unknown"
            if detected_names:
                from collections import Counter
                most_common = Counter(detected_names).most_common(1)
                trojan_name = most_common[0][0] if most_common else detected_names[0]
            
            return {
                'status': 'completed',
                'file_path': file_path,
                'file_hash': file_hash,
                'trojan_name': trojan_name,
                'threat_level': threat_level,
                'detection_method': 'virustotal',
                'detection_rate': f"{malicious}/{total_engines}",
                'malicious_count': malicious,
                'suspicious_count': suspicious,
                'total_engines': total_engines,
                'detailed_results': results,
                'is_malicious': malicious > 0 or suspicious > 0
            }
            
        except Exception as e:
            print(f"❌ Parse error: {str(e)}")
            return None
    
    # ===== PHƯƠNG THỨC MỚI: SCAN FOLDER CHỈ BẰNG API =====
    def scan_folder_api_only(self, folder_path, extensions=None):
        if extensions is None:
            from config.settings import SCAN_EXTENSIONS
            extensions = SCAN_EXTENSIONS
        
        threats_found = []
        files_scanned = 0
        
        # Thu thập danh sách file
        if os.path.isfile(folder_path):
            files_to_scan = [folder_path]
        else:
            files_to_scan = []
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    ext = os.path.splitext(file_path)[1].lower()
                    if ext in extensions:
                        files_to_scan.append(file_path)
        
        print(f"\n{'='*70}")
        print(f"🌐 VIRUSTOTAL API-ONLY SCAN")
        print(f"📂 Files to scan: {len(files_to_scan)}")
        print(f"⚡ Mode: PURE API (no internal checks)")
        print(f"⏱️  Rate limit: 15 seconds between API calls")
        print(f"{'='*70}\n")
        
        # Quét từng file
        for idx, file_path in enumerate(files_to_scan, 1):
            files_scanned += 1
            file_name = os.path.basename(file_path)
            
            print(f"\n[{idx}/{len(files_to_scan)}] 📂 Scanning: {file_name}")
            
            # Tính SHA256 hash
            sha256_hash = calculate_file_hash(file_path, algorithm='sha256')
            if not sha256_hash:
                print("    ⚠️ Cannot calculate hash, skipping...")
                continue
            
            print(f"    🔐 SHA256: {sha256_hash}")
            print(f"    🌐 Querying VirusTotal API...")
            
            # GỌI VIRUSTOTAL API
            vt_result = self.scan_file_by_hash(file_path)
            
            if vt_result and vt_result.get('status') == 'completed':
                print(f"    ✅ VirusTotal API Response: SUCCESS")
                print(f"    📊 Detection Rate: {vt_result['detection_rate']}")
                print(f"    🔢 Engines: {vt_result['total_engines']}")
                
                if vt_result.get('is_malicious'):
                    # PHÁT HIỆN THREAT
                    threats_found.append({
                        'file_path': file_path,
                        'file_hash': vt_result['file_hash'],
                        'trojan_name': f"[VT] {vt_result['trojan_name']}",
                        'threat_level': vt_result['threat_level'],
                        'detection_method': 'virustotal',
                        'vt_detection': vt_result['detection_rate']
                    })
                    print(f"    🔴 VIRUSTOTAL: MALICIOUS DETECTED!")
                    print(f"    🦠 Malware Name: {vt_result['trojan_name']}")
                    print(f"    ⚠️ Threat Level: {vt_result['threat_level'].upper()}")
                else:
                    # FILE CLEAN
                    print(f"    ✅ VIRUSTOTAL: File is CLEAN")
                    print(f"    📊 {vt_result['malicious_count']} malicious / {vt_result['total_engines']} engines")
            
            elif vt_result and vt_result.get('status') == 'not_found':
                print("    ⚠️ File not found in VirusTotal database")
                print("    💡 This file hasn't been uploaded to VT before")
            
            else:
                print("    ❌ VirusTotal API request failed")
        
        # KẾT QUẢ TỔNG
        print(f"\n{'='*70}")
        print(f"📊 VIRUSTOTAL API-ONLY SCAN SUMMARY")
        print(f"{'='*70}")
        print(f"✅ Files Scanned: {files_scanned}")
        print(f"🔴 Threats Found: {len(threats_found)}")
        print(f"🌐 All detections from VirusTotal API")
        print(f"⚡ No internal checks performed")
        print(f"{'='*70}\n")
        
        return files_scanned, threats_found
    
    def get_scan_summary(self, scan_result):

        if not scan_result or scan_result.get('status') != 'completed':
            return "Scan không thành công hoặc file chưa được phân tích"
        
        summary = f"""
╔═══════════════════════════════════════════════════════
║ VIRUSTOTAL SCAN RESULT
╠═══════════════════════════════════════════════════════
║ File: {scan_result['file_path']}
║ Hash: {scan_result['file_hash']}
║ 
║ Detection: {scan_result['detection_rate']} engines
║   • Malicious: {scan_result['malicious_count']}
║   • Suspicious: {scan_result['suspicious_count']}
║   • Total Engines: {scan_result['total_engines']}
║ 
║ Threat Level: {scan_result['threat_level'].upper()}
║ Trojan Name: {scan_result['trojan_name']}
║ 
║ Status: {'🔴 MALICIOUS' if scan_result['is_malicious'] else '✅ CLEAN'}
╚═══════════════════════════════════════════════════════
"""
        return summary

if __name__ == "__main__":
    # Thay YOUR_API_KEY bằng API key thật của bạn
    API_KEY = VIRUSTOTAL_API_KEY
    
    scanner = VirusTotalScanner(API_KEY)
    
    # Test với EICAR file (file test antivirus chuẩn)
    test_file = "path/to/test_file.exe"
    
    print("=" * 60)
    print("TEST 1: Scan by hash (nhanh, không upload)")
    print("=" * 60)
    result = scanner.scan_file_by_hash(test_file)
    
    if result:
        if result['status'] == 'completed':
            print(scanner.get_scan_summary(result))
        elif result['status'] == 'not_found':
            print("\n⚠️ File chưa có trong VirusTotal database")
            print("Thử upload file để scan...")
            
            print("\n" + "=" * 60)
            print("TEST 2: Upload and scan (chậm hơn, cần đợi)")
            print("=" * 60)
            result = scanner.upload_and_scan(test_file)
            
            if result:
                print(scanner.get_scan_summary(result))
    else:
        print("❌ Scan thất bại")