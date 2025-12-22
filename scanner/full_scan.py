from scanner.signature_scanner import SignatureScanner
from scanner.behaviour_scanner import BehaviourScanner
from scanner.dynamic_analysis_api import DynamicAPI
import os

class FullScanner:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.sig_scanner = SignatureScanner(db_manager)
        self.beh_scanner = BehaviourScanner(db_manager)
        self.dynamic_api = DynamicAPI(db_manager)
    
    def _is_valid_executable(self, file_path):
        """Kiểm tra file có phải executable hợp lệ không"""
        try:
            # Kiểm tra tồn tại
            if not os.path.exists(file_path):
                return False, "File không tồn tại"
            
            # Kiểm tra kích thước
            file_size = os.path.getsize(file_path)
            if file_size < 100:
                return False, f"File quá nhỏ ({file_size} bytes)"
            if file_size > 50 * 1024 * 1024:
                return False, f"File quá lớn ({file_size/(1024*1024):.1f}MB)"
            
            # Kiểm tra file extension
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext not in ['.exe', '.bat', '.cmd', '.py']:
                return False, f"File type không hỗ trợ ({file_ext})"
            
            # Kiểm tra PE header cho .exe files
            if file_ext == '.exe':
                try:
                    with open(file_path, 'rb') as f:
                        header = f.read(2)
                        # Chỉ accept PE files (MZ header) hoặc script files
                        if header not in [b'MZ', b'#!']:  # MZ = PE executable
                            return False, "File không phải valid PE executable (missing MZ header)"
                except:
                    return False, "Cannot read file header"
            
            return True, "OK"
        
        except Exception as e:
            return False, str(e)
    
    def scan(self, path, enable_dynamic=True, dynamic_timeout=30):
        """
        Quét toàn diện (signature + behaviour + dynamic chỉ cho files có threat)
        """
        # 1. SIGNATURE SCAN
        print("\n" + "="*70)
        print("📋 SIGNATURE SCANNER")
        print("="*70)
        files_sig, threats_sig = self.sig_scanner.scan(path)
        
        # 2. BEHAVIOR SCAN
        print("\n" + "="*70)
        print("🔎 BEHAVIOUR SCANNER")
        print("="*70)
        files_beh, threats_beh = self.beh_scanner.scan(path)
        
        # Gộp kết quả tĩnh
        all_threats = self.sig_scanner.threats_found + self.beh_scanner.threats_found
        unique_threats = {t['file_path']: t for t in all_threats}.values()
        unique_threats_list = list(unique_threats)
        
        # Lấy danh sách files có threat
        threat_files = list(set([t['file_path'] for t in unique_threats_list]))
        
        # Filter files có thể execute được
        valid_threat_files = []
        invalid_threat_files = []
        
        for threat_file in threat_files:
            is_valid, reason = self._is_valid_executable(threat_file)
            if is_valid:
                valid_threat_files.append(threat_file)
            else:
                invalid_threat_files.append((threat_file, reason))
        
        print(f"\n📌 Identified {len(threat_files)} files with threats")
        print(f"✅ Valid executable files: {len(valid_threat_files)}")
        print(f"⚠️ Skipped (invalid): {len(invalid_threat_files)}")
        
        if invalid_threat_files:
            for invalid_file, reason in invalid_threat_files[:5]:  # Show first 5
                print(f"   • {os.path.basename(invalid_file)}: {reason}")
        
        # 3. DYNAMIC ANALYSIS (chỉ cho files có threat + executable)
        dynamic_results = []
        if enable_dynamic:
            print("\n" + "="*70)
            print("🔬 DYNAMIC ANALYSIS (Threat Files Only)")
            print("="*70)
            
            if valid_threat_files:
                print(f"\n📂 Analyzing {len(valid_threat_files)} valid executable threat files")
                
                # Phân tích từng file có threat
                for idx, threat_file in enumerate(valid_threat_files, 1):
                    file_name = os.path.basename(threat_file)
                    print(f"\n[{idx}/{len(valid_threat_files)}] 🔬 Analyzing: {file_name}")
                    
                    result = self.dynamic_api.analyze(
                        threat_file,
                        timeout=dynamic_timeout,
                        capture_network=False
                    )
                    
                    if result['success']:
                        threat_score = result.get('threat_score', 0)
                        threat_icon = "🔴" if threat_score > 50 else "🟡" if threat_score > 20 else "🟢"
                        
                        print(f"    {threat_icon} Threat score: {threat_score:.1f}/100")
                        print(f"    ⏱️ Duration: {result['duration']:.2f}s")
                        
                        # Log process info
                        summary = result.get('summary', {})
                        if summary.get('process_summary'):
                            proc = summary['process_summary'][0]
                            print(f"    📦 Child processes: {len(proc.get('child_processes', []))}")
                            print(f"    💾 Peak memory: {proc.get('max_memory_mb', 0):.1f}MB")
                        
                        dynamic_results.append({
                            'file': threat_file,
                            'threat_score': threat_score,
                            'run_id': result.get('run_id')
                        })
                    else:
                        error_msg = result.get('error', 'Unknown error')
                        print(f"    ⚠️ Cannot execute: {error_msg}")
            else:
                print(f"\n✅ No valid executable threat files for dynamic analysis")
        
        # SUMMARY
        print("\n" + "="*70)
        print("📊 FULL SCAN SUMMARY")
        print("="*70)
        print(f"✅ Files Scanned: {max(files_sig, files_beh)}")
        print(f"🔴 Static Threats Found: {len(unique_threats_list)}")
        print(f"   • Total threat files: {len(threat_files)}")
        print(f"   • Valid for dynamic analysis: {len(valid_threat_files)}")
        print(f"   • Skipped (invalid): {len(invalid_threat_files)}")
        
        if enable_dynamic:
            print(f"🔬 Dynamic Analysis Completed: {len(dynamic_results)}/{len(valid_threat_files)}")
            
            if dynamic_results:
                high_risk = sum(1 for r in dynamic_results if r['threat_score'] > 50)
                medium_risk = sum(1 for r in dynamic_results if 20 < r['threat_score'] <= 50)
                low_risk = sum(1 for r in dynamic_results if r['threat_score'] <= 20)
                
                print(f"\n   📊 Dynamic Risk Distribution:")
                print(f"      🔴 High Risk (>50): {high_risk}")
                print(f"      🟡 Medium Risk (20-50): {medium_risk}")
                print(f"      🟢 Low Risk (<20): {low_risk}")
        
        print("="*70)
        
        return max(files_sig, files_beh), len(unique_threats_list), unique_threats_list