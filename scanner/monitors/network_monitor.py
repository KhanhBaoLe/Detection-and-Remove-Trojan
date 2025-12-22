import threading
from datetime import datetime

class NetworkMonitor:
    def __init__(self, target_pid, timeout=30, enabled=False):
        self.target_pid = target_pid
        self.timeout = timeout
        self.enabled = enabled
        self.records = []
        self.running = False
        self.monitor_thread = None
        
    def start(self):
        """Bắt đầu monitoring"""
        if not self.enabled:
            self.records.append({
                'timestamp': datetime.now().isoformat(),
                'note': 'Network monitoring disabled for safety'
            })
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def _monitor_loop(self):
        """Vòng lặp monitor network"""
        import time
        import psutil
        
        start_time = time.time()
        
        while self.running:
            if time.time() - start_time > self.timeout:
                self.running = False
                break
            
            try:
                # Lấy network connections
                connections = psutil.net_connections()
                process_conns = [c for c in connections if c.pid == self.target_pid]
                
                for conn in process_conns:
                    record = {
                        'timestamp': datetime.now().isoformat(),
                        'pid': conn.pid,
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'type': conn.type
                    }
                    self.records.append(record)
            except:
                pass
            
            time.sleep(5)
    
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
        """Tóm tắt network activity"""
        if not self.enabled:
            return {'status': 'disabled'}
        
        connections = [r for r in self.records if 'remote_addr' in r]
        
        return {
            'total_connections': len(connections),
            'connections': connections[:50]
        }