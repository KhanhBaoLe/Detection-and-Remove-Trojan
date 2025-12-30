import threading
import time
import winreg
from datetime import datetime

class RegistryMonitor:
    def __init__(self, timeout=30):
        self.timeout = timeout
        self.running = False
        self.monitor_thread = None
        
        # Danh sách các Key Persistence quan trọng cần theo dõi
        # Malware thường ghi vào đây để tự khởi động cùng Windows
        self.MONITORED_KEYS = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            # HKLM yêu cầu quyền Admin, tool sẽ tự bỏ qua nếu không có quyền
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Services"),
        ]
        
        self.initial_snapshot = {} # Trạng thái ban đầu
        self.changes = []          # Danh sách thay đổi phát hiện được

    def start(self):
        # 1. Chụp ảnh trạng thái Registry trước khi chạy malware
        self._take_snapshot(self.initial_snapshot)
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop(self):
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1)

    def _monitor_loop(self):
        start_time = time.time()
        
        while self.running:
            if time.time() - start_time > self.timeout:
                break
            
            # 2. Chụp trạng thái hiện tại
            current_snapshot = {}
            self._take_snapshot(current_snapshot)
            
            # 3. So sánh tìm sự thay đổi (Diff)
            self._compare_snapshots(current_snapshot)
            
            time.sleep(2) # Check mỗi 2 giây để đỡ tốn CPU

    def _take_snapshot(self, snapshot_dict):
        """Đọc toàn bộ value trong các key được theo dõi"""
        for hkey, subkey in self.MONITORED_KEYS:
            try:
                # Mở Key với quyền đọc
                with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key_handle:
                    full_path = str(hkey) + "\\" + subkey
                    if full_path not in snapshot_dict:
                        snapshot_dict[full_path] = {}
                    
                    # Duyệt qua các values (Tên chương trình, Đường dẫn)
                    try:
                        i = 0
                        while True:
                            # EnumValue trả về: (Name, Value, Type)
                            name, value, _ = winreg.EnumValue(key_handle, i)
                            snapshot_dict[full_path][name] = str(value)
                            i += 1
                    except OSError:
                        pass # Đã duyệt hết value
            except PermissionError:
                pass # Không có quyền đọc (thường là HKLM nếu ko chạy Admin)
            except FileNotFoundError:
                pass # Key không tồn tại

    def _compare_snapshots(self, current_snapshot):
        """So sánh snapshot hiện tại với snapshot ban đầu để tìm Key MỚI"""
        for key_path, values in current_snapshot.items():
            # Nếu key path này ban đầu không có (ít gặp)
            if key_path not in self.initial_snapshot:
                continue
                
            old_values = self.initial_snapshot[key_path]
            
            for name, value in values.items():
                # Nếu value name này chưa từng có trong quá khứ -> MỚI ĐƯỢC TẠO
                if name not in old_values:
                    # Tạo ID duy nhất để tránh ghi trùng log
                    event_id = f"{key_path}\\{name}"
                    
                    # Kiểm tra xem đã log chưa
                    already_logged = any(c['id'] == event_id for c in self.changes)
                    
                    if not already_logged:
                        self.changes.append({
                            "id": event_id,
                            "timestamp": datetime.now().isoformat(),
                            "type": "persistence_created",
                            "key_path": key_path,
                            "value_name": name,
                            "value_data": value # Đây thường là đường dẫn file malware
                        })

    def get_summary(self):
        """Mapping dữ liệu cho ThreatScorer"""
        return {
            "status": "ok",
            "total_changes": len(self.changes),
            "persistence_changes": self.changes # Scorer sẽ check list này
        }