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

        # Danh sách Port "đen" thường được Trojan/RAT sử dụng
        self.SENSITIVE_PORTS = {
            # RATs / Backdoors
            4444: "Metasploit/Shell",
            1604: "DarkComet RAT",
            1177: "NjRAT",
            8080: "Alt HTTP/Proxy",
            81:   "Alt Web (Common C2)",
            
            # Exploits / Botnets
            135:  "RPC (Exploit)",
            445:  "SMB (WannaCry/Exploit)",
            3389: "RDP (Remote Access)",
            6667: "IRC (Botnet C2)",
            
            # Data Exfiltration
            21:   "FTP (Data Theft)",
            23:   "Telnet (Insecure)",
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
        # Dùng set để lưu các kết nối đã ghi nhận nhằm tránh trùng lặp
        seen_connections = set() 

        while self.running:
            if time.time() - start_time > self.timeout:
                break

            try:
                connections = psutil.net_connections(kind="inet")
                for c in connections:
                    # Chỉ bắt kết nối của Process mục tiêu
                    if c.pid != self.target_pid:
                        continue
                    
                    # Tạo ID duy nhất: (IP đích, Port đích, Trạng thái)
                    conn_id = (
                        c.raddr.ip if c.raddr else "N/A", 
                        c.raddr.port if c.raddr else 0,
                        c.status
                    )

                    # Chỉ ghi nhận nếu là kết nối mới
                    if conn_id not in seen_connections:
                        seen_connections.add(conn_id)
                        
                        self.records.append({
                            "timestamp": datetime.now().isoformat(),
                            "pid": c.pid,
                            "local_addr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                            "remote_addr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                            "remote_port": c.raddr.port if c.raddr else 0,
                            "status": c.status,
                            "type": str(c.type)
                        })
            except:
                pass

            # [TỐI ƯU HÓA]
            # Tăng từ 0.1s lên 0.5s để giảm tải CPU.
            # Trojan thường giữ kết nối lâu (Beacon) hoặc mở cổng Listen nên 0.5s là đủ bắt.
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
                # Chỉ check trong danh sách đen đã định nghĩa
                if port in self.SENSITIVE_PORTS:
                    detected_sensitive_ports.add(f"{port} ({self.SENSITIVE_PORTS[port]})")
                
        return {
            "status": "ok",
            "total_connections": len(self.records),
            "unique_remote_hosts": list(unique_hosts),
            "exploit_ports": list(detected_sensitive_ports), 
            "traffic_log": self.records
        }