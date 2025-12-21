import tkinter as tk
from tkinter import messagebox, filedialog, ttk, simpledialog, scrolledtext
from datetime import datetime
import threading
import os
import shutil
from database.db_manager import DatabaseManager
from scanner.signature_scanner import SignatureScanner
from scanner.behaviour_scanner import BehaviourScanner
from scanner.full_scan import FullScanner
from scanner.virustotal_scanner import VirusTotalScanner  # ← CHỈ IMPORT FILE NÀY
from config.settings import QUARANTINE_DIR

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
        
        # === LOG FRAME ===
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
        """Scan PURE VirusTotal API - KHÔNG CHẠY LOGIC NỘI BỘ"""
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
                # ===== SỬ DỤNG virustotal_scanner.py - PHƯƠNG THỨC scan_folder_api_only() =====
                self.log_message("🌐 Initializing VirusTotal API scanner...")
                self.log_message("⚡ No EICAR/Signature/Behaviour checks")
                self.log_message("🔒 Using virustotal_scanner.py")
                
                vt_scanner = VirusTotalScanner(self.vt_api_key)
                
                # GỌI PHƯƠNG THỨC MỚI: scan_folder_api_only()
                files_scanned, threats = vt_scanner.scan_folder_api_only(path)
                threats_count = len(threats)
                
                # Log VirusTotal proof
                if threats:
                    self.log_message(f"✅ VirusTotal API responded successfully")
                    self.log_message(f"📊 Detected by VirusTotal: {threats_count} threats")
                    for threat in threats[:3]:  # Show first 3
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
                msg += f"\n📊 Check log for details"
            
            self.log_message(f"✅ Scan #{scan_id} completed")
            messagebox.showinfo("Scan Complete", msg)
            
        except Exception as e:
            import traceback
            self.log_message(f"❌ Error: {str(e)}")
            self.log_message(f"🐛 Traceback:\n{traceback.format_exc()}")
            messagebox.showerror("Error", f"Scan failed: {str(e)}")
    
    def remove_threats(self):
        if not self.current_scan_id:
            messagebox.showwarning("Warning", "Please run a scan first!")
            return
        
        detections = self.db.get_detections_by_scan(self.current_scan_id)
        if not detections:
            messagebox.showinfo("Info", "No threats to remove!")
            return
        
        if messagebox.askyesno("Confirm", f"Move {len(detections)} threats to quarantine?"):
            removed = 0
            for detection in detections:
                try:
                    if os.path.exists(detection.file_path):
                        filename = os.path.basename(detection.file_path)
                        dest = os.path.join(QUARANTINE_DIR, f"{detection.id}_{filename}")
                        shutil.move(detection.file_path, dest)
                        
                        self.db.mark_as_removed(detection.id)
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
        """Export chi tiết để thuyết trình"""
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
        
        scans = self.db.get_all_scans(limit=50)
        for scan in scans:
            detections = self.db.get_detections_by_scan(scan.id)
            removed_count = sum(1 for d in detections if d.is_removed)
            
            self.tree.insert('', 'end', values=(
                scan.id,
                scan.scan_type,
                scan.scan_path[:25] + '...' if len(scan.scan_path) > 25 else scan.scan_path,
                scan.start_time.strftime('%Y-%m-%d %H:%M:%S') if scan.start_time else '',
                scan.files_scanned,
                scan.threats_found,
                removed_count,
                scan.status
            ))
    
    def refresh_all(self):
        self.load_scan_history()
        stats = self.db.get_statistics()
        stats['threats_removed'] = self.db.get_removed_count()
        for key, value in stats.items():
            if key in self.stats_labels:
                self.stats_labels[key].config(text=str(value))
    
    def run(self):
        self.root.mainloop()