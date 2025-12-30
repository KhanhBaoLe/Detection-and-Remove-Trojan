import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime

import psutil

from config.settings import (
    DYNAMIC_ENABLE_NETWORK,
    DYNAMIC_FIREWALL_GUARD_ENABLED,
    DYNAMIC_SANDBOX_DIR,
)
from scanner.monitors.fs_monitor import FileSystemMonitor
from scanner.monitors.network_monitor import NetworkMonitor
from scanner.monitors.process_monitor import ProcessMonitor

from scanner.monitors.registry_monitor import RegistryMonitor 
from utils.logger import setup_logger

logger = setup_logger(__name__)


class SandboxNetworkGuard:
    """
    Best-effort network isolation using Windows firewall rules.
    Falls back silently if not supported or lacking privileges.
    """
    def __init__(self, program_path: str):
        self.program_path = program_path
        self.rule_name = f"TrojanScanner_Block_{int(time.time() * 1000)}"
        self.applied = False

    def apply(self):
        if os.name != "nt":
            logger.info("Network guard skipped: Windows only")
            return False
        if not os.path.exists(self.program_path):
            logger.info("Network guard skipped: sample missing at %s", self.program_path)
            return False
        if shutil.which("netsh") is None:
            logger.info("Network guard skipped: netsh not available on PATH")
            return False

        try:
            for direction in ("out", "in"):
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={self.rule_name}", f"dir={direction}",
                    "action=block", f"program={self.program_path}",
                    "enable=yes", "profile=any",
                ]
                subprocess.run(cmd, capture_output=True, text=True)
            
            self.applied = True
            logger.info("Applied sandbox network block for %s", self.program_path)
            return True
        except Exception as exc:
            logger.warning("Network block apply failed: %s", exc)
            return False

    def remove(self):
        if not self.applied or os.name != "nt":
            return
        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={self.rule_name}",
            ]
            subprocess.run(cmd, capture_output=True)
            logger.info("Removed sandbox network block rule %s", self.rule_name)
        except Exception as exc:
            logger.warning("Network block cleanup failed: %s", exc)


class ExecutionResult:
    def __init__(
        self,
        sample_path,
        exit_code,
        process_monitors=None,
        fs_monitors=None,
        network_monitors=None,
        registry_monitors=None,
        duration=0,
        status="completed",
        reason=None,
        sandbox_dir=None,
        copied_sample=None
    ):
        self.sample_path = sample_path
        self.exit_code = exit_code
        self.duration = duration
        self.status = status
        self.reason = reason
        self.timestamp = datetime.now().isoformat()
        self.sandbox_dir = sandbox_dir
        self.copied_sample = copied_sample

        self.process_monitors = process_monitors or []
        self.fs_monitors = fs_monitors or []
        self.network_monitors = network_monitors or []
        self.registry_monitors = registry_monitors or [] 
        
    def to_dict(self):
        return {
            "sample_path": self.sample_path,
            "exit_code": self.exit_code,
            "status": self.status,
            "reason": self.reason,
            "duration": self.duration,
            "timestamp": self.timestamp,
            "sandbox_dir": self.sandbox_dir,
            "copied_sample": self.copied_sample,
            
            # SUMMARIES
            "process_summary": [m.get_summary() for m in self.process_monitors],
            "fs_summary": [m.get_summary() for m in self.fs_monitors],
            "network_summary": [m.get_summary() for m in self.network_monitors],
            "registry_summary": [m.get_summary() for m in self.registry_monitors], 

            # EVENTS (Trimmed for logs)
            "process_events": [getattr(m, "get_summary", lambda: {})().get("raw_events", [])[:50] for m in self.process_monitors],
            "fs_events": [getattr(m, "get_records", lambda: [])()[:50] for m in self.fs_monitors],
            "network_events": [getattr(m, "get_summary", lambda: {})().get("traffic_log", [])[:50] for m in self.network_monitors],
        }


class DynamicRunner:
    def __init__(
        self,
        timeout_seconds=30,
        enable_network=DYNAMIC_ENABLE_NETWORK,
        use_firewall_guard=None,
    ):
        self.timeout = timeout_seconds
        self.enable_network = enable_network
        self.use_firewall_guard = (
            DYNAMIC_FIREWALL_GUARD_ENABLED if use_firewall_guard is None else use_firewall_guard
        )
        self.process = None
        self.monitors = []
        self.sandbox_dir = None
        self.network_guard = None

    def run_sample(self, sample_path, env_opts=None):
        if not os.path.exists(sample_path):
            raise FileNotFoundError(f"Sample not found: {sample_path}")

        start_time = time.time()
        sandbox_dir = tempfile.mkdtemp(prefix="dyn_", dir=DYNAMIC_SANDBOX_DIR)
        self.sandbox_dir = sandbox_dir

        # Tạo các thư mục giả lập
        for d in ["tmp", "appdata", "home"]:
            os.makedirs(os.path.join(sandbox_dir, d), exist_ok=True)

        copied_sample = os.path.join(sandbox_dir, os.path.basename(sample_path))
        shutil.copy2(sample_path, copied_sample)

        try:
            # ===== PREPARE ENV =====
            env = os.environ.copy()
            if env_opts: env.update(env_opts)
            
            env.update({
                "TEMP": os.path.join(sandbox_dir, "tmp"),
                "TMP": os.path.join(sandbox_dir, "tmp"),
                "APPDATA": os.path.join(sandbox_dir, "appdata"),
                "LOCALAPPDATA": os.path.join(sandbox_dir, "appdata"),
                "USERPROFILE": os.path.join(sandbox_dir, "home"),
            })

            if not self.enable_network and self.use_firewall_guard:
                self.network_guard = SandboxNetworkGuard(copied_sample)
                self.network_guard.apply()

            # ===== EXECUTE SAMPLE =====
            self.process = subprocess.Popen(
                copied_sample,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=sandbox_dir,
                creationflags=0x200 | 0x08000000 
            )

            # ===== INIT MONITORS =====
            # 1. Process Monitor
            process_monitor = ProcessMonitor(self.process.pid, timeout=self.timeout)
            
            # 2. FileSystem Monitor
            fs_monitor = FileSystemMonitor(
                sample_path,
                monitor_dirs=[sandbox_dir, os.path.join(sandbox_dir, "tmp"), os.path.join(sandbox_dir, "appdata")],
                timeout=self.timeout
            )
            
            # 3. Network Monitor
            network_monitor = NetworkMonitor(
                self.process.pid,
                timeout=self.timeout,
                enabled=self.enable_network
            )

            # 4. Registry Monitor
            registry_monitor = RegistryMonitor(timeout=self.timeout)

            self.monitors = [process_monitor, fs_monitor, network_monitor, registry_monitor]

            for monitor in self.monitors:
                monitor.start()

            # ===== WAIT PROCESS =====
            status = "completed"
            reason = None
            try:
                exit_code = self.process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                exit_code = -1
                status = "failed"
                reason = "timeout"

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
                registry_monitors=[registry_monitor], 
                duration=duration,
                status=status,
                reason=reason,
                sandbox_dir=sandbox_dir,
                copied_sample=copied_sample
            )

        except OSError as e:
            if hasattr(e, "winerror") and e.winerror == 216:
                return ExecutionResult(
                    sample_path=copied_sample,
                    exit_code=-216,
                    duration=time.time() - start_time,
                    status="skipped",
                    reason="not_executable"
                )
            self._cleanup()
            raise Exception(f"Dynamic analysis OS error: {str(e)}")

        except Exception as e:
            self._cleanup()
            raise Exception(f"Dynamic analysis failed: {str(e)}")
        finally:
            self._cleanup()

    def _cleanup(self):
        """Cleanup logic"""
        if self.process:
            try:
                psutil.Process(self.process.pid).kill()
            except:
                pass
        
        for monitor in self.monitors:
            try: monitor.stop()
            except: pass

        if self.network_guard:
            try: self.network_guard.remove()
            except: pass

        if self.sandbox_dir:
            try: shutil.rmtree(self.sandbox_dir, ignore_errors=True)
            except: pass

    def terminate(self):
        self._cleanup()