import os
import threading
from datetime import datetime
from pathlib import Path

class FileSystemMonitor:
    def __init__(self, sample_path, monitor_dirs=None, timeout=30):
        self.sample_path = sample_path
        self.monitor_dirs = monitor_dirs or [os.path.expandvars("%APPDATA%"), os.path.expandvars("%TEMP%")]
        self.timeout = timeout
        self.records = []
        self.running = False
        self.monitor_thread = None
        self.initial_state = {}
        self.file_events = []
        
    def start(self):
        """Bắt đầu monitoring"""
        self._capture_initial_state()
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def _capture_initial_state(self):
        """Lưu trạng thái file ban đầu"""
        for monitor_dir in self.monitor_dirs:
            if os.path.exists(monitor_dir):
                try:
                    for root, dirs, files in os.walk(monitor_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                stat = os.stat(file_path)
                                self.initial_state[file_path] = {
                                    'mtime': stat.st_mtime,
                                    'size': stat.st_size
                                }
                            except:
                                pass
                except:
                    pass
    
    def _monitor_loop(self):
        """Vòng lặp monitor"""
        import time
        start_time = time.time()
        
        while self.running:
            if time.time() - start_time > self.timeout:
                self.running = False
                break
            
            try:
                for monitor_dir in self.monitor_dirs:
                    if not os.path.exists(monitor_dir):
                        continue
                    
                    for root, dirs, files in os.walk(monitor_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                stat = os.stat(file_path)
                                mtime = stat.st_mtime
                                size = stat.st_size
                                
                                # Kiểm tra file mới hoặc bị sửa đổi
                                if file_path not in self.initial_state:
                                    self.file_events.append({
                                        'timestamp': datetime.now().isoformat(),
                                        'event_type': 'created',
                                        'file_path': file_path,
                                        'size': size
                                    })
                                else:
                                    if self.initial_state[file_path]['mtime'] != mtime:
                                        self.file_events.append({
                                            'timestamp': datetime.now().isoformat(),
                                            'event_type': 'modified',
                                            'file_path': file_path,
                                            'size': size
                                        })
                            except:
                                pass
            except Exception as e:
                pass
            
            time.sleep(2)
    
    def stop(self):
        """Dừng monitoring"""
        self.running = False
        # Không gọi join() từ trong thread
        if self.monitor_thread and self.monitor_thread != threading.current_thread():
            try:
                self.monitor_thread.join(timeout=2)
            except:
                pass
    
    def get_records(self):
        """Lấy danh sách events"""
        return self.file_events
    
    def get_summary(self):
        """Tóm tắt file changes"""
        created = [e for e in self.file_events if e['event_type'] == 'created']
        modified = [e for e in self.file_events if e['event_type'] == 'modified']
        
        return {
            'files_created': len(created),
            'files_modified': len(modified),
            'created_files': [e['file_path'] for e in created[:20]],
            'modified_files': [e['file_path'] for e in modified[:20]]
        }