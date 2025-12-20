import tkinter as tk
from tkinter import messagebox

def scan_signature():
    messagebox.showinfo("Scan", "Scanning by Signature...")
    
def scan_behaviour():
    messagebox.showinfo("Scan", "Scanning by Behaviour...")
    
def full_scan():
    messagebox.showinfo("Scan", "Full scan running...")
    
def remove_trojan():
    messagebox.showwarning("Remove", "Trojan removed (simulation)")

def show_report():
    messagebox.showinfo("Report", "Showing scan report")
    
def about():
    messagebox.showinfo("About", "Trojan Scanner Demo\nFor Cyber Security Course")
    
def clear_log():
    messagebox.showinfo("Log", "Log cleared")
    
def exit_app():
    root.destroy()
    
# Tạo cửa sổ chính
root = tk.Tk()
root.title("Trojan Detection & Removal")
root.geometry("600x250")

# Frame trên
top_frame = tk.Frame(root)
top_frame.pack(pady=20)

# Frame dưới
bottom_frame = tk.Frame(root)
bottom_frame.pack(pady=20)

# ===== 4 BUTTON TRÊN =====
btn1 = tk.Button(top_frame, text="Signature Scan", width=18, command=scan_signature).grid(row=0, column=0, padx=5)
btn2 = tk.Button(top_frame, text="Behaviour Scan", width=18, command=scan_signature).grid(row=0, column=1, padx=5)
btn3 = tk.Button(top_frame, text="Full Scan", width=18, command=full_scan).grid(row=0, column=2, padx=5)
btn4 = tk.Button(top_frame, text="Remove Trojan", width=18, command=remove_trojan).grid(row=0, column=3, padx=5)

# ===== 4 BUTTON DƯỚI =====
btn5 = tk.Button(bottom_frame, text="View Report", width=18, command=show_report).grid(row=0, column=0, padx=5)
btn6 = tk.Button(bottom_frame, text="Clear Log", width=18, command=clear_log).grid(row=0, column=1, padx=5)
btn7 = tk.Button(bottom_frame, text="About", width=18, command=about).grid(row=0, column=2, padx=5)
btn8 = tk.Button(bottom_frame, text="Exit", width=18, command=exit_app).grid(row=0, column=3, padx=5)

root.mainloop()
