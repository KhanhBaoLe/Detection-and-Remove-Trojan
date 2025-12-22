import psutil
import threading
import json
from datetime import datetime

class ProcessMonitor:
    def __init__(self, target_pid, timeout=30):
        self.target_pid = target_pid
        self.timeout = timeout
        self.records = []
        self.running = False
        self.monitor_thread = None
        self.process_tree = {}
        self.dll_loads = []
        self.cpu_memory = []
        
    def start(self):
        """Bắt đầu monitoring"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def _monitor_loop(self):
        """Vòng lặp monitor"""
        import time
        start_time = time.time()
        
        while self.running:
            if time.time() - start_time > self.timeout:
                self.running = False
                break
            
            try:
                process = psutil.Process(self.target_pid)
                
                # Lấy thông tin process
                info = {
                    'timestamp': datetime.now().isoformat(),
                    'pid': process.pid,
                    'name': process.name(),
                    'status': process.status(),
                    'cpu_percent': process.cpu_percent(interval=0.1),
                    'memory_info': {
                        'rss': process.memory_info().rss,
                        'vms': process.memory_info().vms
                    }
                }
                
                # Lấy child processes
                try:
                    children = process.children(recursive=True)
                    info['children'] = [
                        {
                            'pid': child.pid,
                            'name': child.name(),
                            'cmdline': ' '.join(child.cmdline()) if child.cmdline() else ''
                        }
                        for child in children
                    ]
                except:
                    info['children'] = []
                
                # Lấy open files
                try:
                    open_files = process.open_files()
                    info['open_files'] = [f.path for f in open_files[:50]]
                except:
                    info['open_files'] = []
                
                self.records.append(info)
                self.cpu_memory.append({
                    'timestamp': info['timestamp'],
                    'cpu': info['cpu_percent'],
                    'memory_mb': info['memory_info']['rss'] / (1024*1024)
                })
                
            except psutil.NoSuchProcess:
                # Process kết thúc - thoát vòng lặp
                self.running = False
                break
            except psutil.AccessDenied:
                # Không có quyền truy cập - log và tiếp tục
                self.records.append({
                    'timestamp': datetime.now().isoformat(),
                    'error': 'Access denied'
                })
            except Exception as e:
                self.records.append({
                    'timestamp': datetime.now().isoformat(),
                    'error': str(e)
                })
            
            time.sleep(1)
    
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
        """Lấy danh sách records"""
        return self.records
    
    def get_summary(self):
        """Tóm tắt quá trình"""
        if not self.records:
            return {}
        
        first = self.records[0]
        last = self.records[-1] if self.records else {}
        
        max_memory = max([r['memory_info']['rss'] for r in self.records if 'memory_info' in r], default=0)
        max_cpu = max([r['cpu_percent'] for r in self.records if 'cpu_percent' in r], default=0)
        
        return {
            'start_time': first.get('timestamp'),
            'end_time': last.get('timestamp'),
            'max_memory_mb': max_memory / (1024*1024),
            'max_cpu_percent': max_cpu,
            'child_processes': list(set([
                c['name'] for r in self.records 
                for c in r.get('children', [])
            ])),
            'total_records': len(self.records)
        }