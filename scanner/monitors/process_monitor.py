import threading
import time
import psutil
from datetime import datetime

# Import thư viện WMI và PythonCOM
import wmi
import pythoncom

class ProcessMonitor:
    def __init__(self, target_pid, timeout=30):
        self.target_pid = target_pid
        self.timeout = timeout
        
        self.running = False
        
        # Threads
        self.monitor_thread = None  # Thread dùng WMI để bắt con
        self.stats_thread = None    # Thread dùng psutil để đo RAM
        
        # Data storage
        # Theo dõi cả gia phả: Cha -> Con -> Cháu
        self.monitored_pids = {self.target_pid}
        
        self.events = []
        self.captured_commands = []
        self.process_names = []
        
        # Thống kê tài nguyên
        self.max_mem_mb = 0.0
        self.max_cpu_percent = 0.0

    def start(self):
        """Khởi động bộ giám sát đa luồng"""
        self.running = True
        
        # 1. Luồng WMI: Bắt sự kiện tạo Process (Event-Driven)
        # Giúp không bỏ sót process con nào dù nó chỉ sống 0.1s
        self.monitor_thread = threading.Thread(target=self._wmi_monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        # 2. Luồng Resource: Đo RAM/CPU liên tục (Polling)
        # Giúp phát hiện hành vi ăn RAM (Memory Bomb)
        self.stats_thread = threading.Thread(target=self._resource_monitor_loop, daemon=True)
        self.stats_thread.start()

    def stop(self):
        """Dừng giám sát"""
        self.running = False
        
        # Chờ các thread kết thúc (timeout ngắn để không treo app)
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1)
        if self.stats_thread:
            self.stats_thread.join(timeout=1)

    def _resource_monitor_loop(self):
        """
        Sử dụng psutil để đo tài nguyên của Process đích.
        Chạy tần suất cao (0.1s) để bắt đỉnh RAM (Peak Memory).
        """
        while self.running:
            try:
                # Chỉ tập trung đo process gốc (Malware chính)
                if not psutil.pid_exists(self.target_pid):
                    break # Process đã chết -> Dừng đo
                
                proc = psutil.Process(self.target_pid)
                
                # 1. Đo RAM (RSS - Resident Set Size: RAM thật đang dùng)
                mem_mb = proc.memory_info().rss / (1024 * 1024)
                if mem_mb > self.max_mem_mb:
                    self.max_mem_mb = mem_mb
                
                # 2. Đo CPU (Tùy chọn, interval=None để không block)
                # self.max_cpu_percent = max(self.max_cpu_percent, proc.cpu_percent(interval=None))
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                break
            except Exception:
                pass
            
            # Quét rất nhanh để bắt khoảnh khắc memory spike
            time.sleep(0.1)

    def _wmi_monitor_loop(self):
        """
        Sử dụng WMI để bắt tất cả process con sinh ra từ target_pid.
        """
        # Bắt buộc khởi tạo COM trong thread mới
        pythoncom.CoInitialize()
        
        try:
            c = wmi.WMI()
            # Đăng ký nhận sự kiện khi có Process mới sinh ra
            watcher = c.Win32_Process.watch_for("creation")
            
            start_time = time.time()
            
            while self.running and (time.time() - start_time < self.timeout):
                try:
                    # Chờ sự kiện (timeout 500ms để check flag running)
                    wmi_obj = watcher(timeout_ms=500)
                    
                    parent_pid = wmi_obj.ParentProcessId
                    new_pid = wmi_obj.ProcessId
                    name = wmi_obj.Caption
                    cmdline = wmi_obj.CommandLine or ""

                    # LOGIC GIA PHẢ: Nếu cha nằm trong danh sách theo dõi -> Con cũng bị theo dõi
                    if parent_pid in self.monitored_pids:
                        self.monitored_pids.add(new_pid)
                        self._log_process(new_pid, name, cmdline, parent_pid)
                
                except wmi.x_wmi_timed_out:
                    continue # Hết 500ms không có process mới, lặp lại
                except Exception:
                    pass
                    
        except Exception as e:
            print(f"⚠️ ProcessMonitor WMI Error: {e}")
        finally:
            pythoncom.CoUninitialize()

    def _log_process(self, pid, name, cmdline, parent_pid):
        """Ghi nhận thông tin process mới"""
        self.process_names.append(name)
        self.captured_commands.append(cmdline)
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        self.events.append({
            "timestamp": timestamp,
            "pid": pid,
            "name": name,
            "cmd": cmdline,
            "parent_pid": parent_pid
        })

    def get_summary(self):
        """Tổng hợp kết quả để chấm điểm"""
        
        suspicious_tags = []
        # Các từ khóa nguy hiểm
        shell_keywords = ['cmd.exe', 'powershell', 'wscript', 'cscript', 'bash', 'conhost', 'net.exe', 'whoami']
        
        for name in self.process_names:
            name_lower = name.lower()
            if any(s in name_lower for s in shell_keywords):
                suspicious_tags.append("spawn_shell")
                
        if "svchost.exe" in self.process_names:
            suspicious_tags.append("fake_svchost")

        return {
            "status": "ok",
            "process_tree_count": len(self.monitored_pids) - 1, # Trừ PID gốc
            "processes": self.process_names,
            "command_lines": self.captured_commands,
            "max_memory_mb": self.max_mem_mb, # <--- QUAN TRỌNG: Gửi RAM cho Scorer
            "suspicious_tags": list(set(suspicious_tags)),
            "events": self.events,
            "raw_events": self.events
        }