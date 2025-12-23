import threading
import time
from datetime import datetime
import psutil


class NetworkMonitor:
    def __init__(self, target_pid, timeout=30, enabled=False):
        self.target_pid = target_pid
        self.timeout = timeout
        self.enabled = enabled

        self.records = []
        self.running = False
        self.monitor_thread = None

    # =============================
    # START / STOP
    # =============================
    def start(self):
        if not self.enabled:
            self.records.append({
                "timestamp": datetime.now().isoformat(),
                "note": "network_monitor_disabled"
            })
            return

        self.running = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True
        )
        self.monitor_thread.start()

    def stop(self):
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)

    # =============================
    # MONITOR LOOP
    # =============================
    def _monitor_loop(self):
        start_time = time.time()

        while self.running:
            if time.time() - start_time > self.timeout:
                break

            try:
                connections = psutil.net_connections(kind="inet")
                for c in connections:
                    if c.pid != self.target_pid:
                        continue

                    self.records.append({
                        "timestamp": datetime.now().isoformat(),
                        "pid": c.pid,
                        "local_addr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                        "remote_addr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                        "status": c.status,
                        "type": str(c.type)
                    })
            except:
                pass

            time.sleep(3)

    # =============================
    # SAFE OUTPUT
    # =============================
    def get_records(self):
        return self.records

    def get_summary(self):
        if not self.enabled:
            return {
                "status": "disabled",
                "total_connections": 0,
                "remote_hosts": []
            }

        if not self.records:
            return {
                "status": "no_network_activity",
                "total_connections": 0,
                "remote_hosts": []
            }

        hosts = set()
        for r in self.records:
            remote = r.get("remote_addr")
            if remote:
                hosts.add(remote.split(":")[0])

        return {
            "status": "ok",
            "total_connections": len(self.records),
            "remote_hosts": list(hosts)
        }
