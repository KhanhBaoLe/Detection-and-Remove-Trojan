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
                self.stop()
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
                self.stop()
                break
            except Exception as e:
                self.records.append({
                    'timestamp': datetime.now().isoformat(),
                    'error': str(e)
                })
            
            time.sleep(1)
    
    def stop(self):
        """Dừng monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
    
    def get_records(self):
        """Lấy danh sách records"""
        return self.records
    
    def get_summary(self):
        """
        Tóm tắt quá trình (SAFE)
        """
        if not self.records:
            return {
                "status": "no_runtime_activity",
                "total_records": 0,
                "max_memory_mb": 0,
                "max_cpu_percent": 0,
                "child_processes": []
            }

        max_memory = max(
            (r.get('memory_info', {}).get('rss', 0) for r in self.records),
            default=0
        )

        max_cpu = max(
            (r.get('cpu_percent', 0) for r in self.records),
            default=0
        )

        child_processes = list(set(
            c.get('name')
            for r in self.records
            for c in r.get('children', [])
            if isinstance(c, dict)
        ))

        return {
            "status": "ok",
            "total_records": len(self.records),
            "max_memory_mb": max_memory / (1024 * 1024),
            "max_cpu_percent": max_cpu,
            "child_processes": child_processes
        }
