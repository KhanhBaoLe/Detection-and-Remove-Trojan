import subprocess
import os
import time
import shutil
import tempfile
from datetime import datetime
from config.settings import DYNAMIC_SANDBOX_DIR

from scanner.monitors.process_monitor import ProcessMonitor
from scanner.monitors.fs_monitor import FileSystemMonitor
from scanner.monitors.network_monitor import NetworkMonitor


class ExecutionResult:
    def __init__(
        self,
        sample_path,
        exit_code,
        process_monitors=None,
        fs_monitors=None,
        network_monitors=None,
        duration=0,
        status="completed",
        reason=None
    ):
        self.sample_path = sample_path
        self.exit_code = exit_code
        self.duration = duration
        self.status = status          # completed | skipped | failed
        self.reason = reason          # not_executable | timeout | error
        self.timestamp = datetime.now().isoformat()

        self.process_monitors = process_monitors or []
        self.fs_monitors = fs_monitors or []
        self.network_monitors = network_monitors or []

    def to_dict(self):
        return {
            "sample_path": self.sample_path,
            "exit_code": self.exit_code,
            "status": self.status,
            "reason": self.reason,
            "duration": self.duration,
            "timestamp": self.timestamp,
            "process_summary": [m.get_summary() for m in self.process_monitors],
            "fs_summary": [m.get_summary() for m in self.fs_monitors],
            "network_summary": [m.get_summary() for m in self.network_monitors],
        }


class DynamicRunner:
    def __init__(self, timeout_seconds=30, enable_network=False):
        self.timeout = timeout_seconds
        self.enable_network = enable_network
        self.process = None
        self.monitors = []

    def run_sample(self, sample_path, env_opts=None):
        """
        Khởi chạy mẫu và thu thập hành vi runtime
        """

        if not os.path.exists(sample_path):
            raise FileNotFoundError(f"Sample not found: {sample_path}")

        start_time = time.time()
        sandbox_dir = tempfile.mkdtemp(prefix="dyn_", dir=DYNAMIC_SANDBOX_DIR)
        copied_sample = os.path.join(sandbox_dir, os.path.basename(sample_path))
        shutil.copy2(sample_path, copied_sample)

        try:
            # ===== PREPARE ENV =====
            env = os.environ.copy()
            if env_opts:
                env.update(env_opts)

            # ===== EXECUTE SAMPLE =====
            self.process = subprocess.Popen(
                copied_sample,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=sandbox_dir,
                creationflags=0x200  # CREATE_NEW_PROCESS_GROUP (Windows)
            )

            # ===== INIT MONITORS =====
            process_monitor = ProcessMonitor(self.process.pid, timeout=self.timeout)
            fs_monitor = FileSystemMonitor(sample_path, timeout=self.timeout)
            network_monitor = NetworkMonitor(
                self.process.pid,
                timeout=self.timeout,
                enabled=self.enable_network
            )

            self.monitors = [process_monitor, fs_monitor, network_monitor]

            for monitor in self.monitors:
                monitor.start()

            # ===== WAIT PROCESS =====
            try:
                exit_code = self.process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                exit_code = -1

            # ===== STOP MONITORS =====
            for monitor in self.monitors:
                monitor.stop()

            duration = time.time() - start_time

            return ExecutionResult(
                sample_path=sample_path,
                exit_code=exit_code,
                process_monitors=[process_monitor],
                fs_monitors=[fs_monitor],
                network_monitors=[network_monitor],
                duration=duration,
                status="completed"
            )

        # ==========================================================
        # FIX: HANDLE WINERROR 216 (NOT A VALID WINDOWS EXECUTABLE)
        # ==========================================================
        except OSError as e:
            if hasattr(e, "winerror") and e.winerror == 216:
                duration = time.time() - start_time

                return ExecutionResult(
                    sample_path=copied_sample,
                    exit_code=-216,
                    duration=duration,
                    status="skipped",
                    reason="not_executable"
                )

            # Cleanup for other OS errors
            self._cleanup()
            raise Exception(f"Dynamic analysis OS error: {str(e)}")

        except Exception as e:
            self._cleanup()
            raise Exception(f"Dynamic analysis failed: {str(e)}")
        finally:
            try:
                shutil.rmtree(sandbox_dir, ignore_errors=True)
            except Exception:
                pass

    def _cleanup(self):
        """Terminate process and stop monitors safely"""
        if self.process:
            try:
                self.process.kill()
            except:
                pass

        for monitor in self.monitors:
            try:
                monitor.stop()
            except:
                pass

    def terminate(self):
        self._cleanup()
