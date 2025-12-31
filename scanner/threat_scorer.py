import os

class ThreatScorer:
    # Các Port nguy hiểm thường dùng bởi Malware/Exploit
    BAD_PORTS = {
        4444: "Metasploit Shell",
        3333: "Crypto Mining",
        6667: "IRC Botnet",
        135: "RPC Exploit",
        445: "SMB Exploit (WannaCry)",
        21: "FTP Exfiltration",
        23: "Telnet Insecure"
    }

    # Các từ khóa cực kỳ nguy hiểm trong dòng lệnh
    CRITICAL_KEYWORDS = [
        "mimikatz", "powershell -enc", "bypass", "bitstransfer", 
        "vssadmin delete shadows", # Lệnh xóa backup của Ransomware
        "bcdedit /set", # Tắt recovery
        "wbadmin delete", "downloadstring", "invoke-expression"
    ]

    @staticmethod
    def calculate_score(process_data, network_data, file_data, registry_data=None):
        """
        Tính điểm Threat Score (0-100) dựa trên dữ liệu tổng hợp từ 4 Monitors.
        """
        score = 0
        reasons = []
        registry_data = registry_data or {}

        # =================================================================
        # 1. PROCESS ANALYSIS (Hành vi tiến trình) - Max: 50 điểm
        # =================================================================
        cmd_lines = process_data.get("command_lines", [])
        procs = process_data.get("processes", [])
        max_ram = process_data.get("max_memory_mb", 0)
        shell_count = sum(1 for p in procs if p.lower() in ['cmd.exe', 'powershell.exe', 'wscript.exe'])
        # Nếu ăn hơn 100MB -> Đáng ngờ (+20)
        if max_ram > 100:
            score += 20
            reasons.append(f"High Memory Usage detected ({max_ram:.1f} MB)")
            
        # Nếu ăn hơn 300MB -> Rất nguy hiểm/DoS (+40)
        if max_ram > 300:
            score += 20 # Cộng tiếp 20 nữa là 40
            reasons.append("Critical Memory Spike (Potential DoS/Bomb)")
        # A. Kiểm tra Shell Spawn (cmd, powershell)
        shell_count = sum(1 for p in procs if p.lower() in ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe'])
        if shell_count > 0:
            pts = 15 + (shell_count * 5) # 1 shell = 20đ, 2 shells = 25đ
            score += pts
            reasons.append(f"Spawning command shells ({shell_count} detected)")

        # B. Kiểm tra lệnh nguy hiểm (Critical Keywords)
        found_critical = False
        for cmd in cmd_lines:
            cmd_lower = cmd.lower()
            for kw in ThreatScorer.CRITICAL_KEYWORDS:
                if kw in cmd_lower:
                    score += 50 # Phạt cực nặng
                    reasons.append(f"Executed CRITICAL command: '{kw}'")
                    found_critical = True
                    break
            if found_critical: break

        # C. Phát hiện giả mạo Process hệ thống (Fake System Process)
        # Ví dụ: svchost.exe chạy từ thư mục Temp thay vì System32
        for p in procs:
            if p.lower() == "svchost.exe":
                # svchost thật không bao giờ được sinh ra bởi user process thông thường
                score += 40
                reasons.append("Detected Fake System Process (svchost.exe)")

        # =================================================================
        # 2. NETWORK ANALYSIS (Hành vi mạng) - Max: 30 điểm
        # =================================================================
        unique_hosts = network_data.get("unique_remote_hosts", [])
        
        # A. Kết nối ra nhiều IP lạ
        if len(unique_hosts) > 0:
            score += 10
            if len(unique_hosts) > 5:
                score += 10
                reasons.append(f"High volume of external connections ({len(unique_hosts)} hosts)")
            else:
                reasons.append("Established external network connection")

        # B. Kiểm tra Port đen (Bad Ports)
        traffic_log = network_data.get("traffic_log", [])
        detected_ports = set()
        
        for log in traffic_log:
            try:
                port = int(log.get("remote_port", 0))
                if port in ThreatScorer.BAD_PORTS:
                    detected_ports.add(port)
            except: pass
        
        if detected_ports:
            score += 40 # Cực kỳ nguy hiểm
            port_names = [f"{p} ({ThreatScorer.BAD_PORTS[p]})" for p in detected_ports]
            reasons.append(f"Connected to BLACKLIST PORTS: {', '.join(port_names)}")

        # =================================================================
        # 3. FILE SYSTEM (Hành vi tập tin) - Max: 60 điểm
        # =================================================================
        files_created = file_data.get("created_files", [])
        files_modified = file_data.get("modified_files", [])
        is_ransomware = file_data.get("is_ransomware_suspect", False) # Cờ từ FS Monitor

        # A. Hành vi Ransomware (Quan trọng nhất)
        if is_ransomware:
            score += 100 # Max khung luôn
            reasons.append("🚨 RANSOMWARE BEHAVIOR DETECTED (Mass file modification)")
        elif len(files_modified) > 5:
            score += 20
            reasons.append(f"Suspicious file modification count ({len(files_modified)} files)")

        # B. Hành vi "Xả rác" (Dropper) - Tạo nhiều file bất kể đuôi gì
        if len(files_created) > 5:
            score += 20
            reasons.append(f"Suspicious mass file creation ({len(files_created)} files)")

        # C. Hành vi Dropper EXE (Thả file thực thi)
        # SỬA LỖI: Thêm .lower() để bắt cả .EXE, .Exe
        exe_drops = [f for f in files_created if f.lower().endswith(('.exe', '.dll', '.bat', '.ps1', '.vbs', '.scr'))]
        if exe_drops:
            score += 30
            display_names = [os.path.basename(f) for f in exe_drops[:3]]
            reasons.append(f"Dropper behavior: Created executables ({', '.join(display_names)}...)")

        # =================================================================
        # 4. REGISTRY / PERSISTENCE (Hành vi bền vững) - Max: 50 điểm
        # =================================================================
        persistence = registry_data.get("persistence_changes", [])
        if persistence:
            score += 50 # Tự khởi động là hành vi rất xấu của malware
            count = len(persistence)
            reasons.append(f"Persistence detected: Added {count} registry Run Keys")

        # =================================================================
        # 5. TỔNG HỢP & CHUẨN HÓA
        # =================================================================
        
        # Logic Combo: Nếu Dropper + Persistence -> Chắc chắn là Trojan
        if exe_drops and persistence:
            score += 20
            reasons.append("[Combo] Dropper + Persistence detected")

        # Giới hạn điểm max là 100
        score = min(100, score)

        # Xếp loại
        threat_name = "Clean"
        level = "low"
        
        if score >= 80: 
            threat_name = "Trojan.Heuristic.Critical"
            level = "critical"
        elif score >= 50: 
            threat_name = "Trojan.Heuristic.High"
            level = "high"
        elif score >= 20: 
            threat_name = "Suspicious.Activity"
            level = "medium"
        elif score > 0:
            threat_name = "Unknown.LowRisk"
            level = "low"

        # Nếu có hành vi Ransomware, đổi tên Threat cho sợ
        if is_ransomware:
            threat_name = "Ransomware.Heuristic.Generic"
            level = "critical"

        return {
            "threat_score": score,
            "threat_level": level,
            "trojan_name": threat_name,
            "reasons": reasons
        }