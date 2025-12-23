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
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name={self.rule_name}",
                    f"dir={direction}",
                    "action=block",
                    f"program={self.program_path}",
                    "enable=yes",
                    "profile=any",
                ]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    output = (result.stderr or result.stdout or "").strip()
                    lowered = output.lower()
                    if "requires elevation" in lowered or "access is denied" in lowered:
                        logger.info(
                            "Network guard skipped; admin privileges required (%s): %s",
                            direction,
                            output or "no output",
                        )
                    else:
                        logger.warning(
                            "Failed to apply network block (%s), continuing without guard: %s",
                            direction,
                            output or "no output",
                        )
                    return False

            self.applied = True
            logger.info("Applied sandbox network block for %s", self.program_path)
            return True
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Network block apply failed: %s", exc)
            return False

    def remove(self):
        if not self.applied or os.name != "nt":
            return
        try:
            cmd = [
                "netsh",
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                f"name={self.rule_name}",
            ]
            subprocess.run(cmd, capture_output=True)
            logger.info("Removed sandbox network block rule %s", self.rule_name)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Network block cleanup failed: %s", exc)


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
        reason=None,
        sandbox_dir=None,
        copied_sample=None
    ):
        self.sample_path = sample_path
        self.exit_code = exit_code
        self.duration = duration
        self.status = status          # completed | skipped | failed
        self.reason = reason          # not_executable | timeout | error
        self.timestamp = datetime.now().isoformat()
        self.sandbox_dir = sandbox_dir
        self.copied_sample = copied_sample

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
            "sandbox_dir": self.sandbox_dir,
            "copied_sample": self.copied_sample,
            "process_summary": [m.get_summary() for m in self.process_monitors],
            "fs_summary": [m.get_summary() for m in self.fs_monitors],
            "network_summary": [m.get_summary() for m in self.network_monitors],
            # Trimmed raw events for richer behaviour logs
            "process_events": [
                getattr(m, "get_records", lambda: [])()[:50]
                for m in self.process_monitors
            ],
            "fs_events": [
                getattr(m, "get_records", lambda: [])()[:50]
                for m in self.fs_monitors
            ],
            "network_events": [
                getattr(m, "get_records", lambda: [])()[:50]
                for m in self.network_monitors
            ],
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
        """
        Khởi chạy mẫu và thu thập hành vi runtime
        """

        if not os.path.exists(sample_path):
            raise FileNotFoundError(f"Sample not found: {sample_path}")

        start_time = time.time()
        sandbox_dir = tempfile.mkdtemp(prefix="dyn_", dir=DYNAMIC_SANDBOX_DIR)
        self.sandbox_dir = sandbox_dir

        sandbox_temp = os.path.join(sandbox_dir, "tmp")
        sandbox_appdata = os.path.join(sandbox_dir, "appdata")
        sandbox_home = os.path.join(sandbox_dir, "home")
        for d in [sandbox_temp, sandbox_appdata, sandbox_home]:
            os.makedirs(d, exist_ok=True)

        copied_sample = os.path.join(sandbox_dir, os.path.basename(sample_path))
        shutil.copy2(sample_path, copied_sample)

        try:
            # ===== PREPARE ENV =====
            env = os.environ.copy()
            if env_opts:
                env.update(env_opts)

            sandbox_env = {
                "TEMP": sandbox_temp,
                "TMP": sandbox_temp,
                "APPDATA": sandbox_appdata,
                "LOCALAPPDATA": sandbox_appdata,
                "USERPROFILE": sandbox_home,
                "HOME": sandbox_home,
            }
            env.update(sandbox_env)

            # Apply firewall rule to block outbound/inbound traffic when disabled
            if not self.enable_network and self.use_firewall_guard:
                self.network_guard = SandboxNetworkGuard(copied_sample)
                self.network_guard.apply()

            if not self.enable_network:
                # Best-effort network hardening for sandboxed runs
                env["NO_PROXY"] = "*"
                for proxy_key in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"]:
                    env[proxy_key] = ""

            # ===== EXECUTE SAMPLE =====
            self.process = subprocess.Popen(
                copied_sample,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=sandbox_dir,
                creationflags=0x200 | 0x08000000  # CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
            )

            # ===== INIT MONITORS =====
            process_monitor = ProcessMonitor(self.process.pid, timeout=self.timeout)
            fs_monitor = FileSystemMonitor(
                sample_path,
                monitor_dirs=[sandbox_dir, sandbox_temp, sandbox_appdata],
                timeout=self.timeout
            )
            network_monitor = NetworkMonitor(
                self.process.pid,
                timeout=self.timeout,
                enabled=self.enable_network
            )

            self.monitors = [process_monitor, fs_monitor, network_monitor]

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
                duration=duration,
                status=status,
                reason=reason,
                sandbox_dir=sandbox_dir,
                copied_sample=copied_sample
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
                if self.network_guard:
                    self.network_guard.remove()
            finally:
                try:
                    shutil.rmtree(sandbox_dir, ignore_errors=True)
                except Exception:
                    pass

    def _terminate_process_tree(self):
        """Kill the process and any children to enforce cleanup."""
        if not self.process:
            return

        try:
            proc = psutil.Process(self.process.pid)
            for child in proc.children(recursive=True):
                try:
                    child.kill()
                except Exception:
                    continue
            proc.kill()
        except Exception:
            try:
                self.process.kill()
            except Exception:
                pass

    def _cleanup(self):
        """Terminate process and stop monitors safely"""
        self._terminate_process_tree()

        for monitor in self.monitors:
            try:
                monitor.stop()
            except:
                pass

        try:
            if self.network_guard:
                self.network_guard.remove()
        except Exception:
            pass

        try:
            if self.sandbox_dir:
                shutil.rmtree(self.sandbox_dir, ignore_errors=True)
        except Exception:
            pass

    def terminate(self):
        self._cleanup()
