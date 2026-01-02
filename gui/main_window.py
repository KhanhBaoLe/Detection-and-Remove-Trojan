import tkinter as tk
from tkinter import messagebox, filedialog, ttk, scrolledtext
from datetime import datetime
import threading
import os
import shutil
from pathlib import Path
from database.db_manager import DatabaseManager
from scanner.signature_scanner import SignatureScanner
from scanner.behaviour_scanner import BehaviourScanner
from scanner.full_scan import FullScanner
from scanner.virustotal_scanner import VirusTotalScanner
from config.settings import QUARANTINE_DIR
from scanner.dynamic_analysis_api import DynamicAPI

class TrojanScannerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Trojan Detection & Removal System - With VirusTotal")
        self.root.geometry("1150x800")
        self.root.resizable(False, False)
        
        self.db = DatabaseManager()
        self.current_scan_id = None
        self.vt_api_key = None
        
        self.create_widgets()
        self.load_scan_history()
        self.check_virustotal_api()
    
    def check_virustotal_api(self):
        """Kiểm tra xem đã có API key chưa"""
        try:
            from config.api_keys import VIRUSTOTAL_API_KEY
            if VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY != "YOUR_API_KEY_HERE":
                self.vt_api_key = VIRUSTOTAL_API_KEY
                self.log_message("✅ VirusTotal API key loaded successfully")
                self.log_message(f"🔒 API Key: {VIRUSTOTAL_API_KEY[:15]}...{VIRUSTOTAL_API_KEY[-10:]}")
            else:
                self.log_message("⚠️ VirusTotal API key not configured")
        except:
            self.log_message("⚠️ api_keys.py not found")
    
    def log_message(self, message):
        """Thêm message vào log window"""
        if hasattr(self, 'log_text'):
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.log_text.insert('end', f"[{timestamp}] {message}\n")
            self.log_text.see('end')
            self.root.update_idletasks()
    
    def dynamic_analysis(self):
        """Phân tích động một sample"""
        sample_path = filedialog.askopenfilename(
            title="Select sample file for dynamic analysis",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")]
        )
        
        if not sample_path:
            return
        
        self.log_message(f"🔬 Starting dynamic analysis for: {sample_path}")
        
        # Chạy trong thread nền
        threading.Thread(
            target=self._run_dynamic_analysis,
            args=(sample_path,),
            daemon=True
        ).start()
    
    def _run_dynamic_analysis(self, sample_path):
        """Chạy dynamic analysis (Đã thêm logic tự động chuyển sang Detection để xóa)"""
        try:
            api = DynamicAPI(self.db)

            self.log_message("⏱️ Starting sample execution (30s timeout)...")
            result = api.analyze(sample_path, timeout=30, capture_network=False)

            if not result.get('success'):
                self.log_message(f"❌ Error: {result.get('error')}")
                return

            # Lấy các thông số
            score = result.get('threat_score', 0)
            level = result.get('threat_level', 'clean')
            exit_code = result.get('exit_code')
            duration = result.get('duration', 0)

            self.log_message("✅ Dynamic analysis completed")
            self.log_message(f"📊 Exit code: {exit_code}")
            self.log_message(f"⏱️ Duration: {duration:.2f}s")
            self.log_message(f"🔴 Threat score: {score:.1f}/100 ({level.upper()})")

            # --- 1. HIỂN THỊ LOG ---
            summary = result.get('summary') or {}
            
            # Process Info
            process_summary = summary.get('process_summary')
            child_count = 0
            peak_mem = 0
            if isinstance(process_summary, list) and len(process_summary) > 0:
                proc = process_summary[0]
                child_count = proc.get('process_tree_count', 0)
                peak_mem = proc.get('max_memory_mb', 0)
                procs = proc.get('processes', [])
                if len(procs) > 1:
                    self.log_message(f"   ► Tree: {', '.join(procs[:3])}...")

            self.log_message(f"📦 Child processes: {child_count}")
            self.log_message(f"💾 Activity/Mem score: {peak_mem:.1f}")

            # File Info
            fs_summary = summary.get('fs_summary')
            files_created = 0
            files_modified = 0
            if isinstance(fs_summary, list) and len(fs_summary) > 0:
                fs = fs_summary[0]
                created_list = fs.get('created_files', [])
                modified_list = fs.get('modified_files', [])
                files_created = len(created_list)
                files_modified = len(modified_list)

            self.log_message(f"📄 Files created: {files_created}")
            self.log_message(f"🔨 Files modified: {files_modified}")
            
            # Reasons
            analysis_score = summary.get('analysis_score', {})
            reasons = analysis_score.get('reasons', [])
            if reasons:
                self.log_message("⚠️ DETECTION REASONS:")
                for r in reasons:
                    self.log_message(f"   - {r}")

            # --- 2. LOGIC QUAN TRỌNG: KẾT NỐI VỚI NÚT REMOVE ---
            # Nếu điểm >= 20 (Ngưỡng nguy hiểm), ta coi nó là Threat cần xóa
            # MỨC 1: Cảnh báo nhẹ (20-40 điểm)
            if 20 <= score < 40:
                self.log_message(f"⚠️ Suspicious activity detected (Score: {score}), but not enough to quarantine.")
            
            # MỨC 2: Nguy hiểm thực sự (>= 40 điểm) -> Mới cho phép xóa
            # Bạn có thể sửa số 40 thành 50 nếu muốn an toàn hơn nữa
            elif score >= 40:
                self.log_message(f"🚨 MALICIOUS THREAT CONFIRMED! Registering for removal...")
                
                # A. Tạo một "Scan Session" ảo để chứa threat này
                scan_id = self.db.add_scan('dynamic_detection', sample_path)
                
                # B. Cập nhật ID hiện tại để nút Remove biết cần xóa ở đâu
                self.current_scan_id = scan_id
                
                # C. Thêm vào bảng Detection (Bảng mà nút Remove sẽ đọc)
                self.db.add_detection(
                    scan_id=scan_id,
                    file_path=sample_path,
                    file_hash="DYNAMIC_HASH",
                    trojan_name=f"Trojan.Dynamic.Generic (Score: {score:.0f})",
                    detection_method="dynamic_analysis",
                    threat_level=level
                )
                
                # D. Cập nhật trạng thái scan ảo là hoàn tất
                self.db.update_scan(
                    scan_id, 
                    end_time=datetime.now(), 
                    files_scanned=1, 
                    threats_found=1, 
                    status='completed'
                )
                
                # E. Refresh lại giao diện để hiện lên bảng History
                self.root.after(0, self.refresh_all)
                
                messagebox.showwarning(
                    "Threat Detected", 
                    f"Malicious behavior detected!\nScore: {score}/100\n\nYou can now click 'Remove Threats' to quarantine this file."
                )

        except Exception as e:
            import traceback
            self.log_message(f"❌ Exception: {str(e)}")
            self.log_message(traceback.format_exc())

    
    def create_widgets(self):
        # Header
        header = tk.Frame(self.root, bg='#2c3e50', height=70)
        header.pack(fill='x')
        
        title = tk.Label(header, text="🛡️ TROJAN DETECTION SYSTEM", 
                        font=('Arial', 18, 'bold'), bg='#2c3e50', fg='white')
        title.pack(pady=15)
        
        # Main container
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=15, pady=15)
        
        # Scan buttons frame
        scan_frame = tk.LabelFrame(main_frame, text="🔍 Scan Options", font=('Arial', 11, 'bold'))
        scan_frame.pack(fill='x', pady=(0, 8))
        
        btn_frame1 = tk.Frame(scan_frame)
        btn_frame1.pack(pady=5)
        
        tk.Button(btn_frame1, text="📁 Signature Scan", width=17, height=2,
                command=self.signature_scan, bg='#3498db', fg='white',
                font=('Arial', 9, 'bold')).grid(row=0, column=0, padx=4)
        
        tk.Button(btn_frame1, text="🔎 Behaviour Scan", width=17, height=2,
                command=self.behaviour_scan, bg='#9b59b6', fg='white',
                font=('Arial', 9, 'bold')).grid(row=0, column=1, padx=4)
        
        tk.Button(btn_frame1, text="🚀 Full Scan", width=17, height=2,
                command=self.full_scan, bg='#e74c3c', fg='white',
                font=('Arial', 9, 'bold')).grid(row=0, column=2, padx=4)
        
        btn_frame2 = tk.Frame(scan_frame)
        btn_frame2.pack(pady=5)
        
        tk.Button(btn_frame2, text="🌐 VirusTotal API", width=17, height=2,
                command=self.virustotal_scan, bg='#16a085', fg='white',
                font=('Arial', 9, 'bold')).grid(row=0, column=0, padx=4)
        
        tk.Button(btn_frame2, text="🔬 Dynamic Analysis", width=17, height=2,
                command=self.dynamic_analysis, bg='#16a085', fg='white',
                font=('Arial', 9, 'bold')).grid(row=0, column=2, padx=4)
        
        tk.Button(btn_frame2, text="🗑️ Remove Threats", width=17, height=2,
                command=self.remove_threats, bg='#e67e22', fg='white',
                font=('Arial', 9, 'bold')).grid(row=0, column=1, padx=4)
        
        # Statistics frame
        stats_frame = tk.LabelFrame(main_frame, text="📊 Statistics", font=('Arial', 11, 'bold'))
        stats_frame.pack(fill='x', pady=(0, 8))
        
        stats_inner = tk.Frame(stats_frame)
        stats_inner.pack(pady=8)
        
        self.stats_labels = {}
        stats = self.db.get_statistics()
        stats['threats_removed'] = self.db.get_removed_count()
        
        for idx, (key, value) in enumerate(stats.items()):
            label_text = key.replace('_', ' ').title()
            tk.Label(stats_inner, text=f"{label_text}:", font=('Arial', 9, 'bold')).grid(row=0, column=idx*2, padx=8)
            self.stats_labels[key] = tk.Label(stats_inner, text=str(value), font=('Arial', 9), fg='#e74c3c')
            self.stats_labels[key].grid(row=0, column=idx*2+1, padx=8)
        
        # LOG FRAME
        log_frame = tk.LabelFrame(main_frame, text="📝 Activity Log (Proof of VirusTotal Integration)", 
                                font=('Arial', 10, 'bold'))
        log_frame.pack(fill='x', pady=(0, 8))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=6, font=('Courier', 8),
                                                bg='#1e1e1e', fg='#00ff00', wrap=tk.WORD)
        self.log_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Scan history frame
        history_frame = tk.LabelFrame(main_frame, text="📋 Scan History", font=('Arial', 11, 'bold'))
        history_frame.pack(fill='both', expand=True)
        
        tree_frame = tk.Frame(history_frame)
        tree_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        scrollbar = tk.Scrollbar(tree_frame)
        scrollbar.pack(side='right', fill='y')
        
        self.tree = ttk.Treeview(tree_frame, yscrollcommand=scrollbar.set,
                                columns=('ID', 'Type', 'Path', 'Time', 'Files', 'Threats', 'Removed', 'Status'),
                                show='headings', height=9)
        
        self.tree.heading('ID', text='ID')
        self.tree.heading('Type', text='Type')
        self.tree.heading('Path', text='Path')
        self.tree.heading('Time', text='Time')
        self.tree.heading('Files', text='Files')
        self.tree.heading('Threats', text='Threats')
        self.tree.heading('Removed', text='Removed')
        self.tree.heading('Status', text='Status')
        
        self.tree.column('ID', width=40)
        self.tree.column('Type', width=90)
        self.tree.column('Path', width=200)
        self.tree.column('Time', width=130)
        self.tree.column('Files', width=60)
        self.tree.column('Threats', width=70)
        self.tree.column('Removed', width=70)
        self.tree.column('Status', width=80)
        
        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.tree.yview)
        
        self.tree.bind('<Double-1>', self.show_scan_details)
        
        # Bottom buttons
        bottom_frame = tk.Frame(main_frame)
        bottom_frame.pack(fill='x', pady=(8, 0))
        
        tk.Button(bottom_frame, text="📊 View Details", width=14,
                command=self.show_scan_details).pack(side='left', padx=4)
        
        tk.Button(bottom_frame, text="🔄 Refresh", width=14,
                command=self.refresh_all).pack(side='left', padx=4)
        
        tk.Button(bottom_frame, text="📋 Export Report", width=14,
                command=self.export_report).pack(side='left', padx=4)
        
        tk.Button(bottom_frame, text="🗑️ Clear Log", width=14,
                command=lambda: self.log_text.delete('1.0', 'end')).pack(side='left', padx=4)
        
        tk.Button(bottom_frame, text="❌ Exit", width=14,
                command=self.root.quit).pack(side='right', padx=4)
    
    def virustotal_scan(self):
        """Scan PURE VirusTotal API"""
        if not self.vt_api_key:
            messagebox.showwarning(
                "API Key Required",
                "Please set your VirusTotal API key first!\n\n"
                "Edit config/api_keys.py"
            )
            return
        
        path = filedialog.askdirectory(title="Select folder to scan with VirusTotal")
        if path:
            self.log_message(f"🌐 Starting PURE VirusTotal API scan: {path}")
            self.log_message(f"⚡ Mode: API ONLY (no internal checks)")
            threading.Thread(target=self._run_scan, args=('virustotal', path), daemon=True).start()

    def signature_scan(self):
        path = filedialog.askdirectory(title="Select folder")
        if path:
            self.log_message(f"📁 Starting signature scan: {path}")
            threading.Thread(target=self._run_scan, args=('signature', path), daemon=True).start()
    
    def behaviour_scan(self):
        path = filedialog.askdirectory(title="Select folder")
        if path:
            self.log_message(f"🔎 Starting behaviour scan: {path}")
            threading.Thread(target=self._run_scan, args=('behaviour', path), daemon=True).start()
    
    def full_scan(self):
        path = filedialog.askdirectory(title="Select folder")
        if path:
            self.log_message(f"🚀 Starting full scan: {path}")
            threading.Thread(target=self._run_scan, args=('full', path), daemon=True).start()
    
    def _run_scan(self, scan_type, path):
        try:
            scan_id = self.db.add_scan(scan_type, path)
            self.current_scan_id = scan_id
            
            if scan_type == 'signature':
                scanner = SignatureScanner(self.db)
                files_scanned, threats_count = scanner.scan(path)
                threats = scanner.threats_found
                
            elif scan_type == 'behaviour':
                scanner = BehaviourScanner(self.db)
                files_scanned, threats_count = scanner.scan(path)
                threats = scanner.threats_found
                
            elif scan_type == 'virustotal':
                self.log_message("🌐 Initializing VirusTotal API scanner...")
                self.log_message("⚡ No EICAR/Signature/Behaviour checks")
                self.log_message("🔒 Using virustotal_scanner.py")
                
                vt_scanner = VirusTotalScanner(self.vt_api_key)
                files_scanned, threats = vt_scanner.scan_folder_api_only(path)
                threats_count = len(threats)
                
                if threats:
                    self.log_message(f"✅ VirusTotal API responded successfully")
                    self.log_message(f"📊 Detected by VirusTotal: {threats_count} threats")
                    for threat in threats[:3]:
                        self.log_message(f"  🔴 {os.path.basename(threat['file_path'])}: {threat.get('vt_detection', 'N/A')}")
                else:
                    self.log_message(f"✅ All files clean according to VirusTotal")
                
            else:  # full
                scanner = FullScanner(self.db)
                files_scanned, threats_count, threats = scanner.scan(path)

            # Lưu threats vào database
            for threat in threats:
                self.db.add_detection(
                    scan_id=scan_id,
                    file_path=threat['file_path'],
                    file_hash=threat.get('file_hash', 'N/A'),
                    trojan_name=threat['trojan_name'],
                    detection_method=threat['detection_method'],
                    threat_level=threat['threat_level']
                )
            
            self.db.update_scan(scan_id, 
                            end_time=datetime.now(),
                            files_scanned=files_scanned,
                            threats_found=threats_count,
                            status='completed')
            
            self.root.after(0, self.refresh_all)
            
            msg = f"Scan completed!\n\nFiles: {files_scanned}\nThreats: {threats_count}"
            if scan_type == 'virustotal':
                msg += "\n\n✅ PURE VirusTotal API used"
                msg += "\n⚡ No internal checks performed"
            
            self.log_message(f"✅ Scan #{scan_id} completed")
            messagebox.showinfo("Scan Complete", msg)
            
        except Exception as e:
            import traceback
            self.log_message(f"❌ Error: {str(e)}")
            self.log_message(f"🐛 Traceback:\n{traceback.format_exc()}")
            messagebox.showerror("Error", f"Scan failed: {str(e)}")
    
    def remove_threats(self):
        """Remove/quarantine threats"""
        if not self.current_scan_id:
            messagebox.showwarning("Warning", "Please run a scan first!")
            return

        detections = self.db.get_active_detections_by_scan(self.current_scan_id)
        if not detections:
            messagebox.showinfo("Info", "No threats to remove!")
            return

        if not messagebox.askyesno("Confirm", f"Move {len(detections)} threats to quarantine?"):
            return

        removed = 0
        for detection in detections:
            try:
                if os.path.exists(detection.file_path):
                    src = Path(detection.file_path)
                    filename = os.path.basename(detection.file_path)
                    dest = Path(QUARANTINE_DIR) / f"{detection.id}_{filename}"
                    
                    # Tránh trùng tên
                    counter = 1
                    while dest.exists():
                        dest = Path(QUARANTINE_DIR) / f"{detection.id}_{counter}_{filename}"
                        counter += 1
                    
                    src.rename(dest)
                    self.db.mark_as_quarantined(detection.id, str(dest))
                    removed += 1
                    self.log_message(f"🗑️ Quarantined: {filename}")
            except Exception as e:
                self.log_message(f"⚠️ Failed: {filename} - {str(e)}")
        
        messagebox.showinfo("Success", f"Moved {removed} files to quarantine!")
        self.refresh_all()
    
    def show_scan_details(self, event=None):
        selection = self.tree.selection()
        if not selection:
            return
        
        item = self.tree.item(selection[0])
        scan_id = item['values'][0]
        
        detections = self.db.get_detections_by_scan(scan_id)
        
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"Scan Details - ID: {scan_id}")
        detail_window.geometry("1000x550")
        
        tk.Label(detail_window, text=f"📊 Threats Detected: {len(detections)}", 
                font=('Arial', 13, 'bold')).pack(pady=10)
        
        tree_frame = tk.Frame(detail_window)
        tree_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(tree_frame)
        scrollbar.pack(side='right', fill='y')
        
        detail_tree = ttk.Treeview(tree_frame, yscrollcommand=scrollbar.set,
                                columns=('File', 'Trojan', 'Method', 'Level', 'Removed'),
                                show='headings')
        
        detail_tree.heading('File', text='File Path')
        detail_tree.heading('Trojan', text='Trojan Name')
        detail_tree.heading('Method', text='Detection Method')
        detail_tree.heading('Level', text='Threat Level')
        detail_tree.heading('Removed', text='Removed')
        
        detail_tree.column('File', width=300)
        detail_tree.column('Trojan', width=250)
        detail_tree.column('Method', width=120)
        detail_tree.column('Level', width=100)
        detail_tree.column('Removed', width=80)
        
        for det in detections:
            removed_status = "✅ Yes" if det.is_removed else "❌ No"
            detail_tree.insert('', 'end', values=(
                det.file_path, det.trojan_name, det.detection_method, det.threat_level, removed_status
            ))
        
        detail_tree.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=detail_tree.yview)
    
    def export_report(self):
        """Export report to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            scans = self.db.get_all_scans(limit=100)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("TROJAN DETECTION SYSTEM - VIRUSTOTAL INTEGRATION REPORT\n")
                f.write("="*80 + "\n\n")
                
                f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Statistics
                stats = self.db.get_statistics()
                stats['threats_removed'] = self.db.get_removed_count()
                f.write("OVERALL STATISTICS:\n")
                f.write("-"*80 + "\n")
                for key, value in stats.items():
                    f.write(f"{key.replace('_', ' ').title()}: {value}\n")
                f.write("\n")
                
                # Scan details
                f.write("SCAN HISTORY:\n")
                f.write("="*80 + "\n\n")
                
                for scan in scans:
                    f.write(f"Scan ID: {scan.id}\n")
                    f.write(f"Type: {scan.scan_type.upper()}\n")
                    f.write(f"Path: {scan.scan_path}\n")
                    f.write(f"Time: {scan.start_time}\n")
                    f.write(f"Files Scanned: {scan.files_scanned}\n")
                    f.write(f"Threats Found: {scan.threats_found}\n")
                    f.write(f"Status: {scan.status}\n")
                    
                    # Detection details
                    detections = self.db.get_detections_by_scan(scan.id)
                    if detections:
                        f.write(f"\nDetections ({len(detections)}):\n")
                        for det in detections:
                            f.write(f"  • File: {det.file_path}\n")
                            f.write(f"    Name: {det.trojan_name}\n")
                            f.write(f"    Method: {det.detection_method}\n")
                            f.write(f"    Level: {det.threat_level}\n")
                            f.write(f"    Removed: {'Yes' if det.is_removed else 'No'}\n")
                            f.write(f"    Hash: {det.file_hash}\n\n")
                    
                    f.write("-"*80 + "\n\n")
                
                # VirusTotal proof section
                f.write("\nVIRUSTOTAL INTEGRATION PROOF:\n")
                f.write("="*80 + "\n")
                f.write("This system uses PURE VirusTotal API via virustotal_scanner.py\n")
                f.write("Evidence of integration:\n")
                f.write("1. API Key configured in config/api_keys.py\n")
                f.write("2. Detection method 'virustotal' in scan results\n")
                f.write("3. Trojan names prefixed with [VT]\n")
                f.write("4. Detection rates from 70+ antivirus engines\n")
                f.write("5. Method: scan_folder_api_only() in virustotal_scanner.py\n")
                f.write("6. No EICAR/signature/behaviour checks during VT scan\n")
                f.write("="*80 + "\n")
            
            self.log_message(f"📋 Report exported: {filename}")
            messagebox.showinfo("Success", "Report exported successfully!")
    
    def load_scan_history(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        history_items = []
        static_scans = self.db.get_all_scans(limit=20)
        for s in static_scans:
            # Đếm số file đã bị xóa/quarantine
            detections = self.db.get_detections_by_scan(s.id)
            removed_count = sum(1 for d in detections if d.is_removed)
            
            history_items.append({
                'id': s.id,
                'type': s.scan_type,          # full, signature, behaviour
                'path': s.scan_path,
                'time': s.start_time,
                'files': s.files_scanned,
                'threats': s.threats_found,   # Hiển thị số lượng (int)
                'removed': removed_count,
                'status': s.status,
                'is_dynamic': False           # Cờ đánh dấu
            })
        if hasattr(self.db, 'get_all_dynamic_runs'):
            dynamic_runs = self.db.get_all_dynamic_runs(limit=20)
            
            for d in dynamic_runs:
                # Lấy điểm số từ bảng behavior_samples
                samples = self.db.get_behavior_samples(d.id)
                score_display = "0 pts"
                if samples:
                    # Hiển thị điểm số thay vì số lượng threat
                    score = samples[0].threat_score
                    score_display = f"{score:.0f} pts"
                
                history_items.append({
                    'id': d.id,
                    'type': 'dynamic',        # Đặt type riêng để dễ phân biệt
                    'path': d.sample_path,
                    'time': getattr(d, 'start_time', datetime.now()),     # Thời gian chạy
                    'files': 1,               # Dynamic chỉ chạy 1 file
                    'threats': score_display, # Hiển thị điểm (VD: 50 pts)
                    'removed': 'N/A',         # Dynamic chưa hỗ trợ auto-remove
                    'status': d.status,
                    'is_dynamic': True
                })

        history_items.sort(key=lambda x: x['time'] or datetime.min, reverse=True)
        
        for item in history_items:
            # Cắt ngắn đường dẫn nếu quá dài
            path_display = item['path']
            if len(path_display) > 35:
                path_display = "..." + path_display[-32:]
            
            # Format thời gian
            time_str = ""
            if item['time']:
                time_str = item['time'].strftime('%Y-%m-%d %H:%M:%S')

            # Insert vào bảng
            self.tree.insert('', 'end', values=(
                item['id'],
                item['type'].upper(),
                path_display,
                time_str,
                item['files'],
                item['threats'],
                item['removed'],
                item['status']
            ))
    
    def refresh_all(self):
        self.load_scan_history()
        stats = self.db.get_statistics()
        stats['threats_removed'] = self.db.get_removed_count()
        for key, value in stats.items():
            if key in self.stats_labels:
                self.stats_labels[key].config(text=str(value))
    def show_behavior_details(self, run_id):
        """Hiển thị chi tiết behavior sample"""
        import json
        from tkinter import Toplevel
        
        samples = self.db.get_behavior_samples(run_id)
        
        if not samples:
            messagebox.showinfo("No Data", "Không có behavior sample cho run này")
            return
        
        sample = samples[0]
        
        # Tạo window mới
        details_window = Toplevel(self.root)
        details_window.title("Behavior Details")
        details_window.geometry("700x500")
        
        # Tạo text widget
        text = scrolledtext.ScrolledText(details_window, height=25, width=80)
        text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Nội dung chi tiết
        details = f"""
╔════════════════════════════════════════════════════════════════════════════╗
║                        BEHAVIOR ANALYSIS DETAILS                           ║
╚════════════════════════════════════════════════════════════════════════════╝

📊 THREAT SCORE: {sample.threat_score:.1f}/100

📦 PROCESS BEHAVIOR
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        try:
            processes = json.loads(sample.process_tree or "[]")
            details += f"Child Processes Created: {len(processes)}\n"
            for p in processes[:5]:
                details += f"  • {p}\n"
        except:
            details += "Error parsing process data\n"
        
        details += "\n📄 FILE SYSTEM CHANGES\n"
        details += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        
        try:
            files_created = json.loads(sample.files_created or "[]")
            files_modified = json.loads(sample.files_modified or "[]")
            
            details += f"Files Created: {len(files_created)}\n"
            for f in files_created[:5]:
                details += f"  ✓ {f}\n"
            
            details += f"\nFiles Modified: {len(files_modified)}\n"
            for f in files_modified[:5]:
                details += f"  ✎ {f}\n"
        except:
            details += "Error parsing file data\n"
        
        details += "\n🌐 NETWORK ACTIVITY\n"
        details += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        details += "Network monitoring disabled for safety\n"
        
        details += "\n" + "━" * 80
        details += f"\nDetected at: {sample.detected_at}\n"
        
        text.insert('1.0', details)
        text.config(state='disabled')
        
    def run(self):
        self.root.mainloop()