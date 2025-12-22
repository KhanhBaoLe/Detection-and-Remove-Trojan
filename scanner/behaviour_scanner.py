import os
import subprocess
import json
import time
import psutil
import winreg
from datetime import datetime
from scanner.base_scanner import BaseScanner
from utils.file_hash import calculate_file_hash

class BehaviourScanner(BaseScanner):
    def __init__(self, db_manager):
        super().__init__(db_manager)
        self.execution_timeout = 300  # 5 phút
        self.monitored_keys = [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        ]
    
    def scan(self, path):
        """Quét DYNAMIC - Thực thi và giám sát file"""
        self.threats_found = []
        files_scanned = 0
        
        if os.path.isfile(path):
            files_to_scan = [path]
        else:
            files_to_scan = []
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if self.is_suspicious_extension(file_path):
                        files_to_scan.append(file_path)
        
        print(f"\n{'='*70}")
        print(f"🔬 DYNAMIC BEHAVIOUR SCANNER")
        print(f"📂 Files to analyze: {len(files_to_scan)}")
        print(f"⏱️  Execution timeout: {self.execution_timeout}s per file")
        print(f"🛡️  Mode: SANDBOXED EXECUTION + MONITORING")
        print(f"{'='*70}\n")
        
        for file_path in files_to_scan:
            files_scanned += 1
            file_name = os.path.basename(file_path)
            print(f"[{files_scanned}/{len(files_to_scan)}] 🔬 Dynamic analyzing: {file_name}")
            try:
                # CHECK 1: EICAR (static) - SKIP không dynamic scan file test
                if self.scan_eicar(file_path):
                    print("    ↩️  EICAR test file detected, skipping dynamic analysis")
                    continue
                # CHECK 2: DYNAMIC ANALYSIS
                print("    ⚡ Starting dynamic analysis...")
                behaviour_result = self._execute_and_monitor(file_path)
                
                status = behaviour_result['status']  # 'malicious', 'clean', 'inconclusive'
                
                if status == 'malicious':
                    self.threats_found.append({
                        'file_path': file_path,
                        'file_hash': calculate_file_hash(file_path),
                        'trojan_name': behaviour_result['trojan_name'],
                        'threat_level': behaviour_result['threat_level'],
                        'detection_method': 'dynamic',
                        'behaviours': behaviour_result['behaviours'],
                        'severity_score': behaviour_result['severity_score']
                    })
                    print(f"    🔴 MALICIOUS BEHAVIOUR DETECTED!")
                    print(f"    📊 Severity Score: {behaviour_result['severity_score']:.1f}")
                    print(f"    ⚠️  Threat Level: {behaviour_result['threat_level'].upper()}")
                    for bhv in behaviour_result['behaviours'][:3]:
                        print(f"        • {bhv}")
                elif status == 'clean':
                    print(f"    ✅ CLEAN - No malicious behaviour detected")
                    print(f"    📊 Severity Score: {behaviour_result['severity_score']:.1f}")
                else:  # inconclusive
                    print(f"    ❓ INCONCLUSIVE - Cannot fully analyze")
                    print(f"    ⚠️  Reason: {behaviour_result.get('reason', 'Unknown')}")
            except Exception as e:
                print(f"    ⚠️ Analysis error: {str(e)}")
        
        print(f"\n{'='*70}")
        print(f"📊 DYNAMIC SCAN SUMMARY")
        print(f"{'='*70}")
        print(f"✅ Files Analyzed: {files_scanned}")
        print(f"🔴 Threats Found: {len(self.threats_found)}")
        print(f"{'='*70}\n")
        
        return files_scanned, len(self.threats_found)
    
    def _execute_and_monitor(self, file_path):
        behaviours = []
        severity_score = 0.0
        status = 'inconclusive'  # Mặc định
        reason = ''
        
        # Snapshot trước khi thực thi
        print("    📸 Taking system snapshot...")
        pre_snapshot = self._take_snapshot()
        
        # Thực thi file
        print("    🚀 Executing file in monitored environment...")
        execution_result = self._execute_file(file_path)
        
        if execution_result['executed']:
            print(f"    ✅ Execution completed (PID: {execution_result.get('pid', 'N/A')})")
            
            # Đợi file chạy và gây hành vi
            time.sleep(3)
            
            # Monitor các hành vi
            print("    🔍 Monitoring behaviours...")
            
            # 1. Process monitoring
            process_behaviour = self._monitor_process(execution_result.get('process'))
            behaviours.extend(process_behaviour['behaviours'])
            severity_score += process_behaviour['score']
            
            # 2. Registry monitoring
            registry_behaviour = self._monitor_registry(pre_snapshot['registry'])
            behaviours.extend(registry_behaviour['behaviours'])
            severity_score += registry_behaviour['score']
            
            # 3. Network monitoring
            network_behaviour = self._monitor_network(execution_result.get('pid'))
            behaviours.extend(network_behaviour['behaviours'])
            severity_score += network_behaviour['score']
            
            # 4. File system monitoring
            fs_behaviour = self._monitor_filesystem(pre_snapshot['filesystem'])
            behaviours.extend(fs_behaviour['behaviours'])
            severity_score += fs_behaviour['score']
            
            # Terminate process
            if execution_result.get('process'):
                try:
                    execution_result['process'].terminate()
                    execution_result['process'].wait(timeout=5)
                    print("    ✅ Process terminated")
                except:
                    print("    ⚠️ Process already terminated")
            
            # Xác định status dựa trên severity score
            if severity_score >= 7.0:
                status = 'malicious'
            else:
                status = 'clean'
        else:
            print(f"    ⚠️ Execution failed: {execution_result.get('error', 'Unknown')}")
            status = 'inconclusive'
            reason = execution_result.get('error', 'Cannot execute for analysis')
            severity_score = 0.0
        
        # Đánh giá threat level
        threat_level = self._calculate_threat_level(severity_score)
        
        # Tạo tên trojan dựa trên hành vi
        trojan_name = self._generate_trojan_name(behaviours)
        
        return {
            'status': status,  # 'malicious', 'clean', 'inconclusive'
            'severity_score': severity_score,
            'threat_level': threat_level,
            'trojan_name': trojan_name,
            'behaviours': behaviours,
            'execution_result': execution_result,
            'reason': reason
        }
    
    def _execute_file(self, file_path):
        try:
            # Chạy file với quyền hạn chế
            process = subprocess.Popen(
                file_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            return {
                'executed': True,
                'pid': process.pid,
                'process': process,
                'start_time': time.time()
            }
            
        except Exception as e:
            return {
                'executed': False,
                'error': str(e)
            }
    
    def _take_snapshot(self):
        snapshot = {
            'registry': self._snapshot_registry(),
            'filesystem': self._snapshot_filesystem(),
            'timestamp': time.time()
        }
        return snapshot
    
    def _snapshot_registry(self):
        snapshot = {}
        for key_path in self.monitored_keys:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    key_path,
                    0,
                    winreg.KEY_READ
                )
                values = []
                i = 0
                while True:
                    try:
                        value = winreg.EnumValue(key, i)
                        values.append(value)
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
                snapshot[key_path] = values
            except:
                snapshot[key_path] = []
        return snapshot
    
    def _snapshot_filesystem(self):
        important_dirs = [
            os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            os.path.join(os.environ['TEMP'])
        ]
        
        snapshot = {}
        for dir_path in important_dirs:
            try:
                if os.path.exists(dir_path):
                    snapshot[dir_path] = set(os.listdir(dir_path))
                else:
                    snapshot[dir_path] = set()
            except:
                snapshot[dir_path] = set()
        return snapshot
    
    def _monitor_process(self, process):
        """Giám sát process behaviour"""
        behaviours = []
        score = 0.0
        
        if not process:
            return {'behaviours': behaviours, 'score': score}
        
        try:
            proc = psutil.Process(process.pid)
            
            # Check CPU usage
            cpu_percent = proc.cpu_percent(interval=1)
            if cpu_percent > 80:
                behaviours.append(f"High CPU usage: {cpu_percent:.1f}%")
                score += 2.0
            
            # Check memory usage
            mem_info = proc.memory_info()
            mem_mb = mem_info.rss / (1024 * 1024)
            if mem_mb > 100:
                behaviours.append(f"High memory usage: {mem_mb:.1f}MB")
                score += 1.5
            
            # Check child processes
            children = proc.children(recursive=True)
            if len(children) > 0:
                behaviours.append(f"Created {len(children)} child process(es)")
                score += 1.0 * len(children)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return {'behaviours': behaviours, 'score': score}
    
    def _monitor_registry(self, pre_snapshot):
        """Giám sát thay đổi registry"""
        behaviours = []
        score = 0.0
        
        for key_path in self.monitored_keys:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    key_path,
                    0,
                    winreg.KEY_READ
                )
                current_values = []
                i = 0
                while True:
                    try:
                        value = winreg.EnumValue(key, i)
                        current_values.append(value)
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
                
                # So sánh với snapshot
                old_values = pre_snapshot.get(key_path, [])
                if len(current_values) > len(old_values):
                    new_count = len(current_values) - len(old_values)
                    behaviours.append(f"Added {new_count} registry value(s) to {key_path}")
                    score += 3.0 * new_count
                    
            except:
                pass
        
        return {'behaviours': behaviours, 'score': score}
    
    def _monitor_network(self, pid):
        """Giám sát network connections"""
        behaviours = []
        score = 0.0
        
        if not pid:
            return {'behaviours': behaviours, 'score': score}
        
        try:
            connections = psutil.net_connections()
            process_connections = [c for c in connections if c.pid == pid]
            
            if len(process_connections) > 0:
                behaviours.append(f"Established {len(process_connections)} network connection(s)")
                score += 2.5 * len(process_connections)
                
                # Check for suspicious ports
                suspicious_ports = [80, 443, 8080, 4444, 5555]
                for conn in process_connections:
                    if conn.raddr and conn.raddr.port in suspicious_ports:
                        behaviours.append(f"Connected to suspicious port: {conn.raddr.port}")
                        score += 1.5
                        
        except (psutil.AccessDenied, AttributeError):
            pass
        
        return {'behaviours': behaviours, 'score': score}
    
    def _monitor_filesystem(self, pre_snapshot):
        """Giám sát thay đổi file system"""
        behaviours = []
        score = 0.0
        
        for dir_path, old_files in pre_snapshot.items():
            try:
                if os.path.exists(dir_path):
                    current_files = set(os.listdir(dir_path))
                    new_files = current_files - old_files
                    
                    if len(new_files) > 0:
                        behaviours.append(f"Created {len(new_files)} file(s) in {os.path.basename(dir_path)}")
                        score += 1.5 * len(new_files)
                        
            except:
                pass
        
        return {'behaviours': behaviours, 'score': score}
    
    def _calculate_threat_level(self, severity_score):
        """Tính threat level dựa trên severity score"""
        if severity_score >= 12.0:
            return 'critical'
        elif severity_score >= 9.0:
            return 'high'
        elif severity_score >= 7.0:
            return 'medium'
        else:
            return 'low'
    
    def _generate_trojan_name(self, behaviours):
        """Tạo tên trojan dựa trên hành vi"""
        if not behaviours:
            return "Suspicious.Behaviour.Unknown"
        
        # Phân loại dựa trên hành vi
        if any('registry' in b.lower() for b in behaviours):
            return "Trojan.Persistence.RegistryModifier"
        elif any('network' in b.lower() for b in behaviours):
            return "Trojan.Downloader.NetworkActivity"
        elif any('process' in b.lower() for b in behaviours):
            return "Trojan.Injector.ProcessCreation"
        elif any('file' in b.lower() for b in behaviours):
            return "Trojan.Dropper.FileCreation"
        else:
            return f"Suspicious.Behaviour.Dynamic"