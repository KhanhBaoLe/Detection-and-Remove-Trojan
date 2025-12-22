import os
from scanner.signature_scanner import SignatureScanner
from scanner.behaviour_scanner import BehaviourScanner

class FullScanner:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.sig_scanner = SignatureScanner(db_manager)
        self.beh_scanner = BehaviourScanner(db_manager)
    
    def scan(self, path):
        print(f"\n{'='*70}")
        print("🚀 FULL SCAN STARTED (Static + Selective Dynamic Analysis)")
        print(f"{'='*70}\n")
        
        # STEP 1: Static scan nhanh toàn bộ folder
        print("📋 STEP 1: Running STATIC Scan (Signature-based)")
        print("-" * 70)
        files_scanned_static, threats_static = self.sig_scanner.scan(path)
        static_threats = self.sig_scanner.threats_found.copy()
        print(f"✅ Static scan completed: {len(static_threats)} threats found\n")
        
        # STEP 2: Hệ thống tự chọn 3-5 file nghi ngờ nhất
        print("📊 STEP 2: Selecting top 3-5 most suspicious files for Dynamic Analysis")
        print("-" * 70)
        selected_files = self._select_suspicious_files(path, static_threats)
        print(f"✅ Selected {len(selected_files)} files for dynamic analysis:")
        for file_path in selected_files:
            print(f"   • {file_path}")
        print()
        
        # STEP 3: Với mỗi file được chọn - thực thi trong monitored environment
        print("🔬 STEP 3: Running DYNAMIC Analysis on selected files")
        print("-" * 70)
        dynamic_results = []
        
        if selected_files:
            # Tạo behaviour scanner với list specific files
            dynamic_results = self._run_dynamic_on_selected(selected_files)
            malicious_count = sum(1 for r in dynamic_results if r['status'] == 'malicious')
            clean_count = sum(1 for r in dynamic_results if r['status'] == 'clean')
            inconclusive_count = sum(1 for r in dynamic_results if r['status'] == 'inconclusive')
            print(f"\n✅ Dynamic analysis completed:")
            print(f"   🔴 Malicious: {malicious_count}")
            print(f"   ✅ Clean: {clean_count}")
            print(f"   ❓ Inconclusive: {inconclusive_count}\n")
        else:
            print("⚠️ No suspicious files selected for dynamic analysis\n")
        
        # STEP 4: Kết hợp static + dynamic results
        print("🔀 STEP 4: Combining Static + Dynamic Results")
        print("-" * 70)
        combined_threats = self._merge_results(static_threats, dynamic_results)
        print(f"✅ Combined analysis: {len(combined_threats)} unique threats\n")
        
        # STEP 5: Final report
        print("📈 STEP 5: Final Report")
        print("-" * 70)
        print(f"Total Files Scanned: {files_scanned_static}")
        print(f"Static Threats: {len(static_threats)}")
        dynamic_malicious = sum(1 for r in dynamic_results if r['status'] == 'malicious')
        dynamic_clean = sum(1 for r in dynamic_results if r['status'] == 'clean')
        dynamic_inconclusive = sum(1 for r in dynamic_results if r['status'] == 'inconclusive')
        print(f"Dynamic Results:")
        print(f"   🔴 Malicious: {dynamic_malicious}")
        print(f"   ✅ Clean: {dynamic_clean}")
        print(f"   ❓ Inconclusive: {dynamic_inconclusive}")
        print(f"Total Unique Threats: {len(combined_threats)}")
        print(f"{'='*70}\n")
        
        return files_scanned_static, len(combined_threats), combined_threats
    
    def _select_suspicious_files(self, path, static_threats):
        suspicious_files = []
        
        # Priority 1: Files đã detect trong static scan
        for threat in static_threats:
            if threat['threat_level'] in ['critical', 'high']:
                suspicious_files.append({
                    'path': threat['file_path'],
                    'score': 100,
                    'reason': f"Static threat: {threat['trojan_name']}"
                })

        if os.path.isfile(path):
            files_to_check = [path]
        else:
            files_to_check = []
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.lower().endswith('.exe'):
                        file_path = os.path.join(root, file)
                        files_to_check.append(file_path)
        
        for file_path in files_to_check:
            if any(s['path'] == file_path for s in suspicious_files):
                continue
            
            try:
                file_size = os.path.getsize(file_path)
                
                # Suspicious if small .exe (typical malware)
                if file_path.lower().endswith('.exe') and 10 * 1024 <= file_size <= 2 * 1024 * 1024:
                    suspicious_files.append({
                        'path': file_path,
                        'score': 50,
                        'reason': f"Unknown .exe, size: {file_size/1024:.1f}KB"
                    })
            except:
                pass
        
        # Sort by score and select top 3-5
        suspicious_files.sort(key=lambda x: x['score'], reverse=True)
        selected = suspicious_files[:5]  # Max 5 files
        
        return [s['path'] for s in selected]
    
    def _run_dynamic_on_selected(self, selected_files):
        dynamic_results = []
        
        for file_path in selected_files:
            if not os.path.exists(file_path):
                print(f"  ⚠️ File not found: {file_path}")
                continue
            
            print(f"\n  🔍 Analyzing: {os.path.basename(file_path)}")
            
            # Thực thi file trong monitored environment
            analysis_result = self.beh_scanner._execute_and_monitor(file_path)
            
            status = analysis_result.get('status', 'inconclusive')
            severity_score = analysis_result.get('severity_score', 0.0)
            
            if status == 'malicious':
                print(f"  🔴 MALICIOUS - Hành vi nguy hiểm phát hiện! (Score: {severity_score:.1f})")
            elif status == 'clean':
                print(f"  ✅ CLEAN - Không phát hiện hành vi nguy hiểm (Score: {severity_score:.1f})")
            else:  # inconclusive
                print(f"  ❓ INCONCLUSIVE - Không thể phân tích đầy đủ")
                print(f"     Reason: {analysis_result.get('reason', 'Unknown')}")
            
            # Lưu kết quả
            dynamic_results.append({
                'file_path': file_path,
                'status': status,
                'analysis_result': analysis_result
            })
        
        return dynamic_results
    
    def _merge_results(self, static_threats, dynamic_results):
        merged = {}
        
        # STEP 1: Thêm tất cả static threats
        for threat in static_threats:
            file_path = threat['file_path']
            merged[file_path] = threat.copy()
            merged[file_path]['detection_sources'] = ['static']
            merged[file_path]['dynamic_status'] = None
        
        # STEP 2: Merge dynamic results
        for dynamic_result in dynamic_results:
            file_path = dynamic_result['file_path']
            status = dynamic_result['status']
            analysis_result = dynamic_result['analysis_result']
            
            if file_path in merged:
                # File đã detect ở static
                static_threat = merged[file_path]
                
                # Merge thông tin
                static_threat['detection_sources'].append('dynamic')
                static_threat['dynamic_status'] = status
                
                if status == 'malicious':
                    # Dynamic confirm static detection
                    static_threat['behaviours'] = analysis_result.get('behaviours', [])
                    print(f"    ✅ Confirmed: {os.path.basename(file_path)} is MALICIOUS (both static + dynamic)")
                elif status == 'clean':
                    # Mâu thuẫn: static báo threat nhưng dynamic không thấy
                    # => Giữ static (có thể là signature false positive, nhưng vẫn cẩn thận)
                    print(f"    ⚠️ Warning: {os.path.basename(file_path)} detected by static but clean in dynamic (possible false positive)")
                else:  # inconclusive
                    # Dynamic không thể phân tích, giữ static detection
                    print(f"    ⚠️ {os.path.basename(file_path)}: static detected, dynamic inconclusive (keeping static)")
            else:
                # File mới phát hiện từ dynamic
                if status == 'malicious':
                    new_threat = {
                        'file_path': file_path,
                        'file_hash': 'N/A',
                        'trojan_name': analysis_result['trojan_name'],
                        'threat_level': analysis_result['threat_level'],
                        'detection_method': 'dynamic',
                        'behaviours': analysis_result.get('behaviours', []),
                        'severity_score': analysis_result.get('severity_score', 0.0),
                        'detection_sources': ['dynamic'],
                        'dynamic_status': status
                    }
                    merged[file_path] = new_threat
                    print(f"    🆕 New threat detected: {os.path.basename(file_path)} is MALICIOUS (dynamic only)")
                elif status == 'clean':
                    # File clean - không thêm vào threats
                    print(f"    ✅ {os.path.basename(file_path)} is CLEAN (dynamic)")
                else:  # inconclusive
                    # Không thể xác định - log warning nhưng không thêm vào threats
                    print(f"    ⚠️ {os.path.basename(file_path)}: dynamic analysis inconclusive (not enough info)")
        
        return list(merged.values())