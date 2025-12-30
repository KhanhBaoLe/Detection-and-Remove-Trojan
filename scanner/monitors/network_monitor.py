import threading
import time
from datetime import datetime
import psutil
import socket

class NetworkMonitor:
    def __init__(self, target_pid, timeout=30, enabled=False):
        self.target_pid = target_pid
        self.timeout = timeout
        self.enabled = enabled

        self.records = []
        self.running = False
        self.monitor_thread = None

        
        self.SENSITIVE_PORTS = {
            4444: "Metasploit/Shell",
            8080: "Alt HTTP/Proxy",
            135:  "RPC (Exploit)",
            445:  "SMB (WannaCry/Exploit)",
            3389: "RDP (Remote Access)",
            21:   "FTP (Data Exfiltration)",
            23:   "Telnet (Insecure)",
            6667: "IRC (Botnet C2)",
            53:   "DNS (Tunneling Check)" 
        }

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
            self.monitor_thread.join(timeout=1)

    # =============================
    # MONITOR LOOP
    # =============================
    def _monitor_loop(self):
        start_time = time.time()
        
        # Chỉ quan tâm các kết nối đã thiết lập hoặc đang gửi gói tin
        INTERESTING_STATUSES = {psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT}

        while self.running:
            if time.time() - start_time > self.timeout:
                break

            try:
                # Quét toàn bộ kết nối
                connections = psutil.net_connections(kind="inet")
                
                for c in connections:
                    # 1. LỌC: Chỉ lấy kết nối của PID malware
                    if c.pid != self.target_pid:
                        continue

                    # 2. LỌC: Trạng thái kết nối
                    if c.status not in INTERESTING_STATUSES:
                        continue

                    # 3. XỬ LÝ DỮ LIỆU
                    remote_ip = f"{c.raddr.ip}" if c.raddr else None
                    remote_port = c.raddr.port if c.raddr else None
                    remote_full = f"{remote_ip}:{remote_port}" if remote_ip else None
                    
                    local_ip = f"{c.laddr.ip}" if c.laddr else None

                    # Tránh spam log trùng lặp liên tục
                    if self.records:
                        last = self.records[-1]
                        if last.get("remote_addr") == remote_full and last.get("status") == c.status:
                            continue

                    # Ghi nhận record
                    self.records.append({
                        "timestamp": datetime.now().isoformat(),
                        "pid": c.pid,
                        "local_addr": local_ip,
                        "remote_addr": remote_full,
                        "remote_port": remote_port, 
                        "status": c.status,
                        "protocol": "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                    })

            except Exception:
                pass

            # Polling rate: 0.5s để bắt kết nối nhanh
            time.sleep(0.5)

    # =============================
    # SAFE OUTPUT (Data Mapping cho Scorer)
    # =============================
    def get_summary(self):
        """
        Output chuẩn hóa cho ThreatScorer
        """
        if not self.enabled:
            return {
                "status": "disabled",
                "total_connections": 0,
                "unique_remote_hosts": [],
                "exploit_ports": [], 
                "traffic_log": []
            }

        unique_hosts = set()
        detected_sensitive_ports = set()
        
        for r in self.records:
            # Lấy IP Hosts
            remote_addr = r.get("remote_addr")
            if remote_addr and ":" in remote_addr:
                ip = remote_addr.split(":")[0]
                if ip not in ["127.0.0.1", "localhost", "0.0.0.0"]:
                    unique_hosts.add(ip)

            # Lấy Port nhạy cảm
            port = r.get("remote_port")
            if port:
                # Check trong danh sách đen
                if port in self.SENSITIVE_PORTS:
                    detected_sensitive_ports.add(f"{port} ({self.SENSITIVE_PORTS[port]})")
                # Hoặc port lạ > 10000
                elif port > 10000:
                    detected_sensitive_ports.add(f"{port} (High Port)")

        return {
            "status": "ok",
            "total_connections": len(self.records),
            "unique_remote_hosts": list(unique_hosts),
            "exploit_ports": list(detected_sensitive_ports), 
            "traffic_log": self.records
        }