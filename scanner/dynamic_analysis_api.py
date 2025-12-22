from scanner.dynamic_runner import DynamicRunner, ExecutionResult
from config.settings import DYNAMIC_TIMEOUT_SECONDS, DYNAMIC_ENABLE_NETWORK
import os

class DynamicAPI:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.timeout = DYNAMIC_TIMEOUT_SECONDS
        self.enable_network = DYNAMIC_ENABLE_NETWORK
        
    def analyze(self, sample_path, scan_id=None, timeout=None, capture_network=None):
        """Phân tích động một mẫu hoặc folder"""
        timeout = timeout or self.timeout
        capture_network = capture_network if capture_network is not None else self.enable_network
        
        # Kiểm tra là file hay folder
        if os.path.isdir(sample_path):
            return self._analyze_folder(sample_path, scan_id, timeout, capture_network)
        else:
            return self._analyze_file(sample_path, scan_id, timeout, capture_network)
    
    def _analyze_file(self, sample_path, scan_id=None, timeout=None, capture_network=None):
        """Phân tích một file đơn"""
        try:
            # Pre-check: file size
            if os.path.exists(sample_path):
                file_size = os.path.getsize(sample_path)
                if file_size < 100:
                    return {
                        'success': False,
                        'error': f'File quá nhỏ ({file_size} bytes) - likely not executable'
                    }
            
            # Tạo dynamic run record
            run_id = self.db_manager.add_dynamic_run(
                scan_id=scan_id,
                sample_path=sample_path,
                timeout=timeout
            )
            
            # Khởi chạy runner
            runner = DynamicRunner(
                timeout_seconds=timeout,
                enable_network=capture_network
            )
            
            # Chạy sample
            result = runner.run_sample(sample_path)
            
            # Lưu behavior sample
            behavior_sample = self.db_manager.add_behavior_sample(run_id, result)
            
            # Cập nhật run status
            self.db_manager.update_dynamic_run(
                run_id,
                status='completed',
                exit_code=result.exit_code,
                duration=result.duration
            )
            
            return {
                'success': True,
                'run_id': run_id,
                'sample_id': behavior_sample.id,
                'exit_code': result.exit_code,
                'duration': result.duration,
                'threat_score': behavior_sample.threat_score,
                'summary': result.to_dict()
            }
            
        except Exception as e:
            error_msg = str(e)
            
            if 'run_id' in locals():
                self.db_manager.update_dynamic_run(
                    run_id,
                    status='failed'
                )
            
            return {
                'success': False,
                'error': error_msg
            }
    
    def _analyze_folder(self, folder_path, scan_id=None, timeout=None, capture_network=None):
        """Phân tích tất cả .exe files trong folder"""
        results = {
            'success': True,
            'folder': folder_path,
            'total_files': 0,
            'analyzed_files': 0,
            'successful': 0,
            'failed': 0,
            'files_results': []
        }
        
        try:
            exe_files = []
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    if file.lower().endswith(('.exe', '.bat', '.py')):
                        exe_files.append(os.path.join(root, file))
            
            results['total_files'] = len(exe_files)
            
            if len(exe_files) == 0:
                return {
                    'success': False,
                    'error': f'Không tìm thấy executable files trong folder'
                }
            
            for exe_file in exe_files:
                try:
                    file_result = self._analyze_file(
                        exe_file, 
                        scan_id=scan_id, 
                        timeout=timeout, 
                        capture_network=capture_network
                    )
                    
                    results['analyzed_files'] += 1
                    
                    if file_result['success']:
                        results['successful'] += 1
                        results['files_results'].append({
                            'file': exe_file,
                            'status': 'success',
                            'threat_score': file_result['threat_score'],
                            'run_id': file_result['run_id']
                        })
                    else:
                        results['failed'] += 1
                        results['files_results'].append({
                            'file': exe_file,
                            'status': 'failed',
                            'error': file_result.get('error')
                        })
                    
                except Exception as e:
                    results['failed'] += 1
                    results['analyzed_files'] += 1
                    results['files_results'].append({
                        'file': exe_file,
                        'status': 'failed',
                        'error': str(e)
                    })
            
            return results
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Lỗi phân tích folder: {str(e)}'
            }