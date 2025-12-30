import threading
import time
import pythoncom
import wmi
import psutil
from datetime import datetime

class ProcessMonitor:
    def __init__(self, target_pid, timeout=30):
        self.target_pid = target_pid
        self.timeout = timeout
        
        self.running = False
        self.monitor_thread = None
        
        # --- STORAGE ---
        # Dùng Set để tra cứu O(1) khi lọc process con
        self.monitored_pids = {self.target_pid} 
        
        self.events = []           # Lưu log chi tiết
        self.captured_commands = [] # Chỉ lưu command line để Scorer check
        self.process_names = []     # Chỉ lưu tên process để Scorer check
        
        # Stats
        self.max_cpu = 0.0
        self.max_mem_mb = 0.0

    def start(self):
        
        self.running = True
        # WMI bắt buộc phải chạy trong thread riêng để không block GUI
        self.monitor_thread = threading.Thread(target=self._wmi_worker, daemon=True)
        self.monitor_thread.start()

    def stop(self):
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1)

    def _wmi_worker(self):
        """
        Đây là trái tim của việc giám sát:
        Sử dụng WMI Event Watcher thay vì Polling.
        """
        # QUAN TRỌNG: Khởi tạo COM context cho thread này
        pythoncom.CoInitialize()
        
        try:
            c = wmi.WMI()
            # Theo dõi sự kiện __InstanceCreationEvent của Win32_Process
            watcher = c.Win32_Process.watch_for("creation")
            
            start_time = time.time()
            
            # Vòng lặp lắng nghe sự kiện
            while self.running:
                # Check timeout tổng
                if time.time() - start_time > self.timeout:
                    break

                try:
                    # Lấy thống kê CPU/RAM của tiến trình gốc (nếu còn sống)
                    self._update_performance_stats()

                    # Chờ event (timeout 500ms để loop check lại cờ running)
                    process_event = watcher(timeout_ms=500)
                    
                    # === LOGIC PROCESS TREE ===
                    # Nếu process mới sinh ra có cha (ParentProcessId) nằm trong danh sách
                    # các process ta đang theo dõi -> Nó là con cháu của malware.
                    if process_event.ParentProcessId in self.monitored_pids:
                        # 1. Thêm nó vào danh sách theo dõi (để bắt tiếp cháu chắt)
                        self.monitored_pids.add(process_event.ProcessId)
                        
                        # 2. Thu thập thông tin
                        pid = process_event.ProcessId
                        ppid = process_event.ParentProcessId
                        name = process_event.Name
                        cmd = process_event.CommandLine or ""  # Quan trọng: Lấy full lệnh

                        # 3. Lưu trữ
                        self.events.append({
                            "timestamp": datetime.now().isoformat(),
                            "pid": pid,
                            "ppid": ppid,
                            "name": name,
                            "cmd": cmd
                        })
                        
                        self.process_names.append(name)
                        if cmd:
                            self.captured_commands.append(cmd)

                except wmi.x_wmi_timed_out:
                    # Hết 500ms không có process mới -> lặp lại loop
                    continue
                except Exception as e:
                    # Process có thể đã chết ngay khi vừa tạo, hoặc lỗi WMI
                    continue
                    
        finally:
            pythoncom.CoUninitialize()

    def _update_performance_stats(self):
        """Dùng psutil để lấy CPU/RAM của process gốc (nhẹ nhàng)"""
        try:
            p = psutil.Process(self.target_pid)
            cpu = p.cpu_percent()
            mem = p.memory_info().rss / (1024 * 1024)
            
            if cpu > self.max_cpu: self.max_cpu = cpu
            if mem > self.max_mem_mb: self.max_mem_mb = mem
        except:
            pass

    def get_summary(self):
        """
        Output được chuẩn hóa cho ThreatScorer.py
        """
        # Phân tích sơ bộ các tag nghi ngờ ngay tại Monitor
        suspicious_tags = []
        
        # Check Shell
        shell_keywords = ['cmd.exe', 'powershell', 'wscript', 'cscript', 'bash']
        for name in self.process_names:
            if any(s in name.lower() for s in shell_keywords):
                suspicious_tags.append("spawn_shell")
                break
        
        # Check Injection (thường process con trùng tên process cha hoặc tên hệ thống)
        if "svchost.exe" in self.process_names:
            suspicious_tags.append("fake_svchost")

        return {
            "status": "ok",
            "process_tree_count": len(self.monitored_pids),
            "processes": self.process_names,         # List[str]: ["cmd.exe", "whoami.exe"]
            "command_lines": self.captured_commands, # List[str]: ["cmd /c del...", ...]
            "suspicious_tags": list(set(suspicious_tags)),
            "max_cpu": self.max_cpu,
            "max_memory_mb": self.max_mem_mb,
            "raw_events": self.events # Để debug hoặc hiện chi tiết trên GUI
        }