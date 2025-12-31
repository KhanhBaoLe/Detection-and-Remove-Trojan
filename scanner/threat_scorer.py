import os

class ThreatScorer:
    # 1. Các Port mà Trojan/RAT (Remote Access Trojan) hay dùng
    BAD_PORTS = {
        4444: "Metasploit/Reverse Shell",
        3333: "Crypto Mining (Trojan Miner)",
        6667: "IRC Botnet",
        135: "RPC Exploit",
        21: "FTP (Stealing Data)",
        23: "Telnet",
        8080: "Alternative HTTP (Proxy Trojan)"
    }

    # 2. Từ khóa Trojan (Tập trung vào tải xuống, ẩn mình, lấy thông tin)
    # Đã XÓA các lệnh Ransomware như: vssadmin, bcdedit, wbadmin
    CRITICAL_KEYWORDS = [
        "mimikatz",             # Trộm mật khẩu
        "powershell -enc",      # Mã hóa lệnh để ẩn mình
        "downloadstring",       # Tải payload về (Dropper)
        "invoke-expression",    # Chạy lệnh từ xa
        "bypass",               # Vượt qua bảo mật
        "reg add",              # Ghi vào Registry (Persistence)
        "netsh advfirewall",    # Tắt tường lửa
        "attrib +h",            # Ẩn file
        "schtasks /create"      # Tạo task để tự chạy lại
    ]

    @staticmethod
    def calculate_score(process_data, network_data, file_data, registry_data=None):
        score = 0
        reasons = []
        registry_data = registry_data or {}

        # =================================================================
        # 1. PROCESS (Hành vi tiến trình)
        # =================================================================
        cmd_lines = process_data.get("command_lines", [])
        procs = process_data.get("processes", [])
        
        # Trojan thường cố gắng ẩn mình nên ít khi ăn RAM quá lớn
        # Tuy nhiên nếu là Trojan đào coin thì sẽ ăn CPU/RAM
        max_ram = process_data.get("max_memory_mb", 0)
        if max_ram > 500:
            score += 15
            reasons.append("High Resource Usage (Possible Trojan Miner)")

        # Kiểm tra Shell (Trojan thường gọi cmd để thực thi lệnh ngầm)
        shell_count = sum(1 for p in procs if any(s in p.lower() for s in ['cmd.exe', 'powershell.exe', 'wscript.exe']))
        if shell_count > 0:
            score += 25 + (shell_count * 5)
            reasons.append(f"Spawning hidden shells ({shell_count} detected)")

        # Kiểm tra lệnh nguy hiểm
        for cmd in cmd_lines:
            cmd_lower = cmd.lower()
            for kw in ThreatScorer.CRITICAL_KEYWORDS:
                if kw in cmd_lower:
                    score += 50 # Phạt nặng
                    reasons.append(f"Trojan command detected: '{kw}'")
                    break

        # =================================================================
        # 2. NETWORK (Quan trọng nhất với Trojan/RAT)
        # =================================================================
        # Trojan bắt buộc phải kết nối ra ngoài để nhận lệnh hoặc gửi dữ liệu
        unique_hosts = network_data.get("unique_remote_hosts", [])
        traffic_log = network_data.get("traffic_log", [])
        
        if len(unique_hosts) > 0:
            score += 15 # Có kết nối lạ là đáng ngờ với file exe không rõ nguồn gốc
            reasons.append(f"Established external connection ({len(unique_hosts)} hosts)")

        # Check Port đen
        detected_ports = set()
        for log in traffic_log:
            try:
                port = int(log.get("remote_port", 0))
                if port in ThreatScorer.BAD_PORTS:
                    detected_ports.add(port)
            except: pass
        
        if detected_ports:
            score += 60 # Gần như chắc chắn là RAT/Backdoor
            port_names = [f"{p}" for p in detected_ports]
            reasons.append(f"Connected to C2/Backdoor Ports: {', '.join(port_names)}")

        # =================================================================
        # 3. FILE SYSTEM (Trojan Dropper)
        # =================================================================
        files_created = file_data.get("created_files", [])
        
        # Trojan thường "đẻ" ra file .exe/.dll khác (Dropper)
        exe_drops = [f for f in files_created if f.lower().endswith(('.exe', '.dll', '.bat', '.ps1', '.vbs'))]
        
        if exe_drops:
            score += 40
            reasons.append(f"Dropper Behavior: Created {len(exe_drops)} executable files")

        # =================================================================
        # 4. PERSISTENCE (Sự bền vững - Đặc trưng của Trojan)
        # =================================================================
        # Trojan luôn muốn khởi động cùng Windows
        persistence = registry_data.get("persistence_changes", [])
        if persistence:
            score += 50 
            reasons.append("Persistence Detected: Added to Startup/Registry")

        # =================================================================
        # 5. KẾT LUẬN
        # =================================================================
        score = min(100, score)

        if score >= 70: 
            threat_name = "Trojan.Heuristic.Critical"
            level = "critical"
        elif score >= 40: 
            threat_name = "Trojan.Heuristic.High"
            level = "high"
        elif score >= 20: 
            threat_name = "Suspicious.TrojanLike"
            level = "medium"
        else:
            threat_name = "Clean"
            level = "low"

        return {
            "threat_score": score,
            "threat_level": level,
            "trojan_name": threat_name,
            "reasons": reasons
        }