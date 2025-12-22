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
from scanner.virustotal_scanner import VirusTotalScanner
from config.settings import QUARANTINE_DIR

class TrojanScannerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Trojan Detection & Removal System - Static + Dynamic Analysis")
        self.root.geometry("1200x850")
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
        header = tk.Frame(self.root, bg='#2c3e50', height=80)
        header.pack(fill='x')
        
        title = tk.Label(header, text="🛡️ TROJAN DETECTION SYSTEM", 
                        font=('Arial', 18, 'bold'), bg='#2c3e50', fg='white')
        title.pack(pady=10)
        
        subtitle = tk.Label(header, text="Static Scan + Dynamic Behaviour Analysis", 
                           font=('Arial', 10), bg='#2c3e50', fg='#ecf0f1')
        subtitle.pack()
        
        # Main container
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=15, pady=15)
        
        # Scan buttons frame
        scan_frame = tk.LabelFrame(main_frame, text="🔍 Scan Options", font=('Arial', 11, 'bold'))
        scan_frame.pack(fill='x', pady=(0, 8))
        
        btn_frame = tk.Frame(scan_frame)
        btn_frame.pack(pady=8)
        
        # ROW 1
        row1 = tk.Frame(btn_frame)
        row1.pack(pady=4)
        
        tk.Button(row1, text="📋 Static Scan\n(Signature)", width=18, height=3,
                 command=self.signature_scan, bg='#3498db', fg='white',
                 font=('Arial', 9, 'bold')).grid(row=0, column=0, padx=5)
        
        tk.Button(row1, text="🔬 Dynamic Scan\n(Behaviour)", width=18, height=3,
                 command=self.behaviour_scan, bg='#9b59b6', fg='white',
                 font=('Arial', 9, 'bold')).grid(row=0, column=1, padx=5)
        
        tk.Button(row1, text="🚀 Full Scan\n(Static + Dynamic)", width=18, height=3,
                 command=self.full_scan, bg='#e74c3c', fg='white',
                 font=('Arial', 9, 'bold')).grid(row=0, column=2, padx=5)
        
        # ROW 2
        row2 = tk.Frame(btn_frame)
        row2.pack(pady=4)
        
        tk.Button(row2, text="🌐 VirusTotal API", width=18, height=2,
                 command=self.virustotal_scan, bg='#16a085', fg='white',
                 font=('Arial', 9, 'bold')).grid(row=0, column=0, padx=5)
        
        tk.Button(row2, text="🗑️ Remove Threats", width=18, height=2,
                 command=self.remove_threats, bg='#e67e22', fg='white',
                 font=('Arial', 9, 'bold')).grid(row=0, column=1, padx=5)
        
        # Info labels
        info_frame = tk.Frame(scan_frame)
        info_frame.pack(pady=5)
        
        tk.Label(info_frame, text="💡 Static = Fast signature check | Dynamic = Execute & Monitor | Full = Smart combination", 
                font=('Arial', 8), fg='#7f8c8d').pack()
        
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
        log_frame = tk.LabelFrame(main_frame, text="📜 Activity Log", 
                                  font=('Arial', 10, 'bold'))
        log_frame.pack(fill='x', pady=(0, 8))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=7, font=('Courier', 8),
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
                                show='headings', height=8)
        
        self.tree.heading('ID', text='ID')
        self.tree.heading('Type', text='Type')
        self.tree.heading('Path', text='Path')
        self.tree.heading('Time', text='Time')
        self.tree.heading('Files', text='Files')
        self.tree.heading('Threats', text='Threats')
        self.tree.heading('Removed', text='Removed')
        self.tree.heading('Status', text='Status')
        
        self.tree.column('ID', width=40)
        self.tree.column('Type', width=120)
        self.tree.column('Path', width=250)
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
    
    def signature_scan(self):
        """Static Scan - Nhanh"""
        path = filedialog.askdirectory(title="Select folder for STATIC scan")
        if path:
            self.log_message(f"📋 Starting STATIC scan: {path}")
            self.log_message(f"⚡ Mode: Signature-based detection (Fast)")
            threading.Thread(target=self._run_scan, args=('signature', path), daemon=True).start()
    
    def behaviour_scan(self):
        """Dynamic Scan - Execute & Monitor"""
        # Ask user to choose between file or folder
        choice = messagebox.askyesnocancel(
            "Scan Selection",
            "Choose what to scan:\n\n"
            "YES = Scan a single file\n"
            "NO = Scan a folder"
        )
        
        if choice is None:  # Cancel
            return
        
        if choice:  # Yes - scan single file
            path = filedialog.askopenfilename(
                title="Select file for DYNAMIC scan",
                filetypes=[("All files", "*.*"), ("Executable", "*.exe"), ("DLL", "*.dll"), ("Scripts", "*.ps1 *.bat *.cmd *.vbs")]
            )
        else:  # No - scan folder
            path = filedialog.askdirectory(title="Select folder for DYNAMIC scan")
        
        if path:
            result = messagebox.askyesno(
                "Dynamic Analysis Warning",
                "⚠️ Dynamic scan will EXECUTE files in a monitored environment.\n\n"
                "This may:\n"
                "• Use significant CPU/Memory\n"
                "• Take 5+ minutes per file\n"
                "• Trigger Windows Defender\n\n"
                "Continue?"
            )
            if result:
                self.log_message(f"🔬 Starting DYNAMIC scan: {path}")
                self.log_message(f"⚡ Mode: Execute & Monitor behaviour")
                threading.Thread(target=self._run_scan, args=('behaviour', path), daemon=True).start()
    
    def full_scan(self):
        """Full Scan - Smart Static + Selective Dynamic"""
        path = filedialog.askdirectory(title="Select folder for FULL scan")
        if path:
            result = messagebox.askyesno(
                "Full Scan Confirmation",
                "🚀 Full Scan will:\n\n"
                "1. Run STATIC scan on all files (fast)\n"
                "2. Select 3-5 most suspicious files\n"
                "3. Run DYNAMIC analysis on selected files\n"
                "4. Combine results\n\n"
                "This may take 15-30 minutes. Continue?"
            )
            if result:
                self.log_message(f"🚀 Starting FULL scan: {path}")
                self.log_message(f"⚡ Mode: Smart Static + Selective Dynamic")
                threading.Thread(target=self._run_scan, args=('full', path), daemon=True).start()
    
    def virustotal_scan(self):
        """Scan PURE VirusTotal API"""
        if not self.vt_api_key:
            messagebox.showwarning(
                "API Key Required",
                "Please set your VirusTotal API key first!\n\nEdit config/api_keys.py"
            )
            return
        
        path = filedialog.askdirectory(title="Select folder to scan with VirusTotal")
        if path:
            self.log_message(f"🌐 Starting VirusTotal API scan: {path}")
            self.log_message(f"⚡ Mode: API ONLY (no internal checks)")
            threading.Thread(target=self._run_scan, args=('virustotal', path), daemon=True).start()
    
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
                vt_scanner = VirusTotalScanner(self.vt_api_key)
                files_scanned, threats = vt_scanner.scan_folder_api_only(path)
                threats_count = len(threats)
                
            else:  # full
                scanner = FullScanner(self.db)
                files_scanned, threats_count, threats = scanner.scan(path)
            
            # Lưu threats vào database
            for threat in threats:
                # Format behaviours nếu có
                detection_method = threat.get('detection_method', scan_type)
                
                # Tạo trojan name với behaviours info nếu có
                trojan_name = threat['trojan_name']
                if 'behaviours' in threat and threat['behaviours']:
                    behaviours_str = '; '.join(threat['behaviours'][:3])  # Lấy 3 behaviours đầu
                    trojan_name = f"{trojan_name} [{behaviours_str}]"
                
                self.db.add_detection(
                    scan_id=scan_id,
                    file_path=threat['file_path'],
                    file_hash=threat.get('file_hash', 'N/A'),
                    trojan_name=trojan_name,
                    detection_method=detection_method,
                    threat_level=threat['threat_level']
                )
            
            self.db.update_scan(scan_id, 
                              end_time=datetime.now(),
                              files_scanned=files_scanned,
                              threats_found=threats_count,
                              status='completed')
            
            self.root.after(0, self.refresh_all)
            
            # Custom message based on scan type
            if scan_type == 'full':
                static_threats = [t for t in threats if t.get('detection_method') in ['signature', 'static-eicar']]
                dynamic_threats = [t for t in threats if t.get('detection_method') == 'dynamic']
                msg = f"Full Scan completed!\n\nFiles scanned: {files_scanned}\n"
                msg += f"Static threats: {len(static_threats)}\n"
                msg += f"Dynamic threats: {len(dynamic_threats)}\n"
                msg += f"Total threats: {threats_count}"
            elif scan_type == 'behaviour':
                msg = f"Dynamic Scan completed!\n\nFiles analyzed: {files_scanned}\n"
                msg += f"Malicious behaviours: {threats_count}\n\n"
                msg += "⚠️ Check logs for detailed behaviour analysis"
            else:
                msg = f"Scan completed!\n\nFiles: {files_scanned}\nThreats: {threats_count}"
            
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
        detail_window.geometry("1100x600")
        
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
        detail_tree.heading('Trojan', text='Trojan Name / Behaviours')
        detail_tree.heading('Method', text='Detection Method')
        detail_tree.heading('Level', text='Threat Level')
        detail_tree.heading('Removed', text='Removed')
        
        detail_tree.column('File', width=250)
        detail_tree.column('Trojan', width=400)
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
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            scans = self.db.get_all_scans(limit=100)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("TROJAN DETECTION SYSTEM - STATIC + DYNAMIC ANALYSIS REPORT\n")
                f.write("="*80 + "\n\n")
                
                f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                stats = self.db.get_statistics()
                stats['threats_removed'] = self.db.get_removed_count()
                f.write("OVERALL STATISTICS:\n")
                f.write("-"*80 + "\n")
                for key, value in stats.items():
                    f.write(f"{key.replace('_', ' ').title()}: {value}\n")
                f.write("\n")
                
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
            
            self.log_message(f"📋 Report exported: {filename}")
            messagebox.showinfo("Success", "Report exported successfully!")
    
    def load_scan_history(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        scans = self.db.get_all_scans(limit=50)
        for scan in scans:
            detections = self.db.get_detections_by_scan(scan.id)
            removed_count = sum(1 for d in detections if d.is_removed)
            
            # Format scan type display
            scan_type_display = scan.scan_type
            if scan.scan_type == 'signature':
                scan_type_display = '📋 Static'
            elif scan.scan_type == 'behaviour':
                scan_type_display = '🔬 Dynamic'
            elif scan.scan_type == 'full':
                scan_type_display = '🚀 Full'
            elif scan.scan_type == 'virustotal':
                scan_type_display = '🌐 VirusTotal'
            
            self.tree.insert('', 'end', values=(
                scan.id,
                scan_type_display,
                scan.scan_path[:30] + '...' if len(scan.scan_path) > 30 else scan.scan_path,
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