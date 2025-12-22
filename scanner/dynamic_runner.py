import subprocess
import os
import time
import json
from datetime import datetime
import psutil
import threading

from scanner.monitors.process_monitor import ProcessMonitor
from scanner.monitors.fs_monitor import FileSystemMonitor
from scanner.monitors.network_monitor import NetworkMonitor

class ExecutionResult:
    def __init__(self, sample_path, exit_code, process_monitors=None, 
                fs_monitors=None, network_monitors=None, duration=0):
        self.sample_path = sample_path
        self.exit_code = exit_code
        self.duration = duration
        self.process_monitors = process_monitors or []
        self.fs_monitors = fs_monitors or []
        self.network_monitors = network_monitors or []
        self.timestamp = datetime.now().isoformat()
        
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'sample_path': self.sample_path,
            'exit_code': self.exit_code,
            'duration': self.duration,
            'timestamp': self.timestamp,
            'process_summary': [m.get_summary() for m in self.process_monitors],
            'fs_summary': [m.get_summary() for m in self.fs_monitors],
            'network_summary': [m.get_summary() for m in self.network_monitors]
        }


class DynamicRunner:
    def __init__(self, timeout_seconds=30, enable_network=False):
        self.timeout = timeout_seconds
        self.enable_network = enable_network
        self.process = None
        self.monitors = []
        
    def run_sample(self, sample_path, env_opts=None):
        """
        Khởi chạy mẫu và thu thập artifacts
        
        Args:
            sample_path: đường dẫn file để chạy
            env_opts: dict các environment variables
            
        Returns:
            ExecutionResult object
        """
        if not os.path.exists(sample_path):
            raise FileNotFoundError(f"Sample not found: {sample_path}")
        
        # Kiểm tra file type
        file_ext = os.path.splitext(sample_path)[1].lower()
        file_size = os.path.getsize(sample_path)
        
        # Chuẩn bị command dựa trên file type
        if file_ext == '.py':
            import sys
            cmd = [sys.executable, sample_path]
            cmd_type = "Python Script"
        elif file_ext == '.bat' or file_ext == '.cmd':
            cmd = sample_path
            cmd_type = "Batch Script"
        elif file_ext == '.exe':
            # Cho phép file .exe dù không có header PE (vì có thể là test file)
            cmd = sample_path
            cmd_type = "Executable"
        else:
            raise Exception(f"Unsupported file type: {file_ext}. Supported: .exe, .bat, .cmd, .py")
        
        start_time = time.time()
        exit_code = None
        
        try:
            # Tạo environment
            env = os.environ.copy()
            if env_opts:
                env.update(env_opts)
            
            # Khởi chạy process
            try:
                self.process = subprocess.Popen(
                    cmd,
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=0x200  # CREATE_NEW_PROCESS_GROUP on Windows
                )
            except Exception as startup_error:
                # Nếu không chạy được, vẫn ghi lại lỗi nhưng không crash
                self.monitors = []
                duration = time.time() - start_time
                
                result = ExecutionResult(
                    sample_path=sample_path,
                    exit_code=-999,  # Error code
                    process_monitors=[],
                    fs_monitors=[],
                    network_monitors=[],
                    duration=duration
                )
                
                raise Exception(
                    f"Cannot execute file: {str(startup_error)}\n"
                    f"File type: {cmd_type}\n"
                    f"File size: {file_size} bytes\n"
                    f"Note: EICAR test strings và non-executable files sẽ không chạy được"
                )
            
            # Khởi tạo monitors
            process_monitor = ProcessMonitor(self.process.pid, timeout=self.timeout)
            fs_monitor = FileSystemMonitor(sample_path, timeout=self.timeout)
            network_monitor = NetworkMonitor(
                self.process.pid, 
                timeout=self.timeout,
                enabled=self.enable_network
            )
            
            # Bắt đầu monitors
            process_monitor.start()
            fs_monitor.start()
            network_monitor.start()
            
            self.monitors = [process_monitor, fs_monitor, network_monitor]
            
            # Chờ process kết thúc hoặc timeout
            try:
                exit_code = self.process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                try:
                    self.process.wait(timeout=5)
                except:
                    pass
                exit_code = -1
            
            # Dừng monitors
            for monitor in self.monitors:
                monitor.stop()
            
            duration = time.time() - start_time
            
            # Tạo result
            result = ExecutionResult(
                sample_path=sample_path,
                exit_code=exit_code,
                process_monitors=[process_monitor],
                fs_monitors=[fs_monitor],
                network_monitors=[network_monitor],
                duration=duration
            )
            
            return result
            
        except FileNotFoundError as e:
            for monitor in self.monitors:
                monitor.stop()
            raise Exception(f"File not found: {str(e)}")
        
        except Exception as e:
            # Cleanup
            if self.process:
                try:
                    self.process.kill()
                except:
                    pass
            
            for monitor in self.monitors:
                monitor.stop()
            
            error_msg = str(e)
            if "not compatible" in error_msg.lower() or "216" in error_msg:
                raise Exception(
                    f"Executable incompatible with system: {error_msg}\n"
                    f"File: {sample_path} ({file_size} bytes)\n"
                    f"Type: {cmd_type}\n"
                    f"Possible causes: 32-bit vs 64-bit mismatch, corrupted file, or Windows version incompatibility"
                )
            else:
                raise Exception(f"Dynamic analysis failed: {error_msg}")
    
    def terminate(self):
        """Chấm dứt process và monitors"""
        if self.process:
            try:
                self.process.kill()
            except:
                pass
        
        for monitor in self.monitors:
            monitor.stop()