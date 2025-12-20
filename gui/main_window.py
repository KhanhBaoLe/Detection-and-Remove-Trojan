import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from datetime import datetime
import threading
import os
import shutil
from database.db_manager import DatabaseManager
from scanner.signature_scanner import SignatureScanner
from scanner.behaviour_scanner import BehaviourScanner
from scanner.full_scan import FullScanner
from config.settings import QUARANTINE_DIR

class TrojanScannerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Trojan Detection & Removal System")
        self.root.geometry("900x700")
        self.root.resizable(False, False)
        
        self.db = DatabaseManager()
        self.current_scan_id = None
        
        self.create_widgets()
        self.load_scan_history()
    
    def create_widgets(self):
        # Header
        header = tk.Frame(self.root, bg='#2c3e50', height=80)
        header.pack(fill='x')
        
        title = tk.Label(header, text="🛡️ TROJAN DETECTION SYSTEM", 
                        font=('Arial', 20, 'bold'), bg='#2c3e50', fg='white')
        title.pack(pady=20)
        
        # Main container
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Scan buttons frame
        scan_frame = tk.LabelFrame(main_frame, text="Scan Options", font=('Arial', 12, 'bold'))
        scan_frame.pack(fill='x', pady=(0, 10))
        
        btn_frame = tk.Frame(scan_frame)
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="📁 Signature Scan", width=18, height=2,
                 command=self.signature_scan, bg='#3498db', fg='white',
                 font=('Arial', 10, 'bold')).grid(row=0, column=0, padx=5)
        
        tk.Button(btn_frame, text="🔍 Behaviour Scan", width=18, height=2,
                 command=self.behaviour_scan, bg='#9b59b6', fg='white',
                 font=('Arial', 10, 'bold')).grid(row=0, column=1, padx=5)
        
        tk.Button(btn_frame, text="🚀 Full Scan", width=18, height=2,
                 command=self.full_scan, bg='#e74c3c', fg='white',
                 font=('Arial', 10, 'bold')).grid(row=0, column=2, padx=5)
        
        tk.Button(btn_frame, text="🗑️ Remove All Threats", width=18, height=2,
                 command=self.remove_threats, bg='#e67e22', fg='white',
                 font=('Arial', 10, 'bold')).grid(row=0, column=3, padx=5)
        
        # Statistics frame
        stats_frame = tk.LabelFrame(main_frame, text="Statistics", font=('Arial', 12, 'bold'))
        stats_frame.pack(fill='x', pady=(0, 10))
        
        stats_inner = tk.Frame(stats_frame)
        stats_inner.pack(pady=10)
        
        self.stats_labels = {}
        stats = self.db.get_statistics()
        
        for idx, (key, value) in enumerate(stats.items()):
            label_text = key.replace('_', ' ').title()
            tk.Label(stats_inner, text=f"{label_text}:", font=('Arial', 10, 'bold')).grid(row=0, column=idx*2, padx=10)
            self.stats_labels[key] = tk.Label(stats_inner, text=str(value), font=('Arial', 10), fg='#e74c3c')
            self.stats_labels[key].grid(row=0, column=idx*2+1, padx=10)
        
        # Scan history frame
        history_frame = tk.LabelFrame(main_frame, text="Scan History", font=('Arial', 12, 'bold'))
        history_frame.pack(fill='both', expand=True)
        
        # Treeview
        tree_frame = tk.Frame(history_frame)
        tree_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(tree_frame)
        scrollbar.pack(side='right', fill='y')
        
        self.tree = ttk.Treeview(tree_frame, yscrollcommand=scrollbar.set,
                                columns=('ID', 'Type', 'Path', 'Time', 'Files', 'Threats', 'Status'),
                                show='headings', height=12)
        
        self.tree.heading('ID', text='ID')
        self.tree.heading('Type', text='Scan Type')
        self.tree.heading('Path', text='Path')
        self.tree.heading('Time', text='Start Time')
        self.tree.heading('Files', text='Files Scanned')
        self.tree.heading('Threats', text='Threats Found')
        self.tree.heading('Status', text='Status')
        
        self.tree.column('ID', width=40)
        self.tree.column('Type', width=100)
        self.tree.column('Path', width=200)
        self.tree.column('Time', width=150)
        self.tree.column('Files', width=100)
        self.tree.column('Threats', width=100)
        self.tree.column('Status', width=80)
        
        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.tree.yview)
        
        self.tree.bind('<Double-1>', self.show_scan_details)
        
        # Bottom buttons
        bottom_frame = tk.Frame(main_frame)
        bottom_frame.pack(fill='x', pady=(10, 0))
        
        tk.Button(bottom_frame, text="📊 View Details", width=15,
                 command=self.show_scan_details).pack(side='left', padx=5)
        
        tk.Button(bottom_frame, text="🔄 Refresh", width=15,
                 command=self.refresh_all).pack(side='left', padx=5)
        
        tk.Button(bottom_frame, text="📋 Export Report", width=15,
                 command=self.export_report).pack(side='left', padx=5)
        
        tk.Button(bottom_frame, text="❌ Exit", width=15,
                 command=self.root.quit).pack(side='right', padx=5)
    
    def signature_scan(self):
        path = filedialog.askdirectory(title="Select folder to scan")
        if path:
            threading.Thread(target=self._run_scan, args=('signature', path), daemon=True).start()
    
    def behaviour_scan(self):
        path = filedialog.askdirectory(title="Select folder to scan")
        if path:
            threading.Thread(target=self._run_scan, args=('behaviour', path), daemon=True).start()
    
    def full_scan(self):
        path = filedialog.askdirectory(title="Select folder to scan")
        if path:
            threading.Thread(target=self._run_scan, args=('full', path), daemon=True).start()
    
    def _run_scan(self, scan_type, path):
        try:
            # Tạo scan record
            scan_id = self.db.add_scan(scan_type, path)
            self.current_scan_id = scan_id
            
            # Chạy scanner
            if scan_type == 'signature':
                scanner = SignatureScanner(self.db)
                files_scanned, threats_count = scanner.scan(path)
                threats = scanner.threats_found
            elif scan_type == 'behaviour':
                scanner = BehaviourScanner(self.db)
                files_scanned, threats_count = scanner.scan(path)
                threats = scanner.threats_found
            else:  # full
                scanner = FullScanner(self.db)
                files_scanned, threats_count, threats = scanner.scan(path)
            
            # Lưu threats vào database
            for threat in threats:
                self.db.add_detection(
                    scan_id=scan_id,
                    file_path=threat['file_path'],
                    file_hash=threat['file_hash'],
                    trojan_name=threat['trojan_name'],
                    detection_method=threat['detection_method'],
                    threat_level=threat['threat_level']
                )
            
            # Cập nhật scan
            self.db.update_scan(scan_id, 
                              end_time=datetime.now(),
                              files_scanned=files_scanned,
                              threats_found=threats_count,
                              status='completed')
            
            # Refresh UI
            self.root.after(0, self.refresh_all)
            
            msg = f"Scan completed!\n\nFiles scanned: {files_scanned}\nThreats found: {threats_count}"
            messagebox.showinfo("Scan Complete", msg)
            
        except Exception as e:
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
                        removed += 1
                except:
                    pass
            
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
        detail_window.geometry("800x500")
        
        tk.Label(detail_window, text=f"Threats Detected: {len(detections)}", 
                font=('Arial', 14, 'bold')).pack(pady=10)
        
        tree_frame = tk.Frame(detail_window)
        tree_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(tree_frame)
        scrollbar.pack(side='right', fill='y')
        
        detail_tree = ttk.Treeview(tree_frame, yscrollcommand=scrollbar.set,
                                  columns=('File', 'Trojan', 'Method', 'Level'),
                                  show='headings')
        
        detail_tree.heading('File', text='File Path')
        detail_tree.heading('Trojan', text='Trojan Name')
        detail_tree.heading('Method', text='Detection Method')
        detail_tree.heading('Level', text='Threat Level')
        
        detail_tree.column('File', width=350)
        detail_tree.column('Trojan', width=200)
        detail_tree.column('Method', width=100)
        detail_tree.column('Level', width=100)
        
        for det in detections:
            detail_tree.insert('', 'end', values=(
                det.file_path, det.trojan_name, det.detection_method, det.threat_level
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
            with open(filename, 'w') as f:
                f.write("TROJAN DETECTION REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                for scan in scans:
                    f.write(f"Scan ID: {scan.id}\n")
                    f.write(f"Type: {scan.scan_type}\n")
                    f.write(f"Path: {scan.scan_path}\n")
                    f.write(f"Time: {scan.start_time}\n")
                    f.write(f"Files Scanned: {scan.files_scanned}\n")
                    f.write(f"Threats: {scan.threats_found}\n")
                    f.write("-" * 80 + "\n\n")
            
            messagebox.showinfo("Success", "Report exported successfully!")
    
    def load_scan_history(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        scans = self.db.get_all_scans(limit=50)
        for scan in scans:
            self.tree.insert('', 'end', values=(
                scan.id,
                scan.scan_type,
                scan.scan_path[:30] + '...' if len(scan.scan_path) > 30 else scan.scan_path,
                scan.start_time.strftime('%Y-%m-%d %H:%M:%S') if scan.start_time else '',
                scan.files_scanned,
                scan.threats_found,
                scan.status
            ))
    
    def refresh_all(self):
        self.load_scan_history()
        stats = self.db.get_statistics()
        for key, value in stats.items():
            self.stats_labels[key].config(text=str(value))
    
    def run(self):
        self.root.mainloop()