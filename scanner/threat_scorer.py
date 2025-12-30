class ThreatScorer:
    @staticmethod
    def calculate_score(process_data, network_data, file_data, registry_data=None):
        """
        Input: Dictionaries từ get_summary() của 4 monitors
        Output: {score, level, reasons}
        """
        score = 0
        reasons = []
        registry_data = registry_data or {}

        # --- 1. PROCESS ANALYSIS ---
        cmd_lines = process_data.get("command_lines", [])
        procs = process_data.get("processes", [])
        
        # Check Shell spawn
        shell_count = sum(1 for p in procs if p.lower() in ['cmd.exe', 'powershell.exe', 'wscript.exe'])
        if shell_count > 0:
            score += 30 * shell_count
            reasons.append(f"Spawned {shell_count} shell processes")

        # Check Encoded Commands (Base64)
        for cmd in cmd_lines:
            if "-enc" in cmd.lower() or "base64" in cmd.lower():
                score += 50
                reasons.append("Detected Base64 encoded command (Obfuscation)")
                break

        # Check Injection/Persistence keywords
        dangerous_keywords = ["reg add", "schtasks", "vssadmin", "bitsadmin", "bcdedit"]
        for cmd in cmd_lines:
            if any(k in cmd.lower() for k in dangerous_keywords):
                score += 40
                reasons.append(f"Suspicious command execution: {cmd[:30]}...")
        
        # Check Suspicious Tags from Monitor
        tags = process_data.get("suspicious_tags", [])
        if "fake_svchost" in tags:
            score += 60
            reasons.append("Fake svchost.exe detected (Process Masquerading)")

        # --- 2. NETWORK ANALYSIS ---
        if network_data.get("status") == "ok":
            hosts = network_data.get("unique_remote_hosts", [])
            
            exploit_ports = network_data.get("exploit_ports", [])
            
            if len(hosts) > 3: 
                score += 10
                reasons.append(f"Connected to multiple hosts ({len(hosts)})")
            
            if exploit_ports:
                score += 50 
                reasons.append(f"Connected to exploit/sensitive ports: {', '.join(exploit_ports)}")

        # --- 3. FILE SYSTEM ANALYSIS ---
        files_created = file_data.get("created_files", [])
        files_modified = file_data.get("modified_files", [])
        
        # Check Ransomware behavior
        if len(files_modified) > 10:
            score += 60
            reasons.append("Mass file modification detected (Ransomware-like)")

        # Check Dropper behavior
        exe_drops = [f for f in files_created if f.endswith(('.exe', '.dll', '.bat', '.ps1'))]
        if exe_drops:
            score += 30
            reasons.append(f"Dropped executable files: {len(exe_drops)}")

        # Kiểm tra Persistence (Khởi động cùng Windows)
        persistence = registry_data.get("persistence_changes", [])
        if persistence:
            score += 80 
            count = len(persistence)
            reasons.append(f"Persistence detected: Modified {count} registry Run Keys")

        # --- FINALIZE ---
        # Normalize Score
        score = min(100, score)
        
        # Determine Threat Level Logic
        threat_name = "Clean"
        if score >= 80: threat_name = "Trojan.Heuristic.Critical"
        elif score >= 50: threat_name = "Trojan.Heuristic.High"
        elif score >= 20: threat_name = "Suspicious.Activity"

        return {
            "score": score,
            "level": threat_name,
            "reasons": reasons
        }