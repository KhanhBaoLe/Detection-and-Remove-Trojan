🛡️ Trojan Detection & Removal System

> Hệ thống phát hiện và loại bỏ mã độc Trojan đa lớp trên nền tảng Windows.

📖 Giới thiệu
Trojan Detection System là một công cụ bảo mật được thiết kế để phát hiện, phân tích và loại bỏ các phần mềm độc hại (Malware), đặc biệt tập trung vào Trojan. Hệ thống áp dụng mô hình bảo mật đa lớp (Multi-layer Security), kết hợp giữa các phương pháp truyền thống và hiện đại để đảm bảo độ chính xác cao nhất.

Dự án này được xây dựng cho mục đích học tập và nghiên cứu về An toàn thông tin, minh họa cách hoạt động của một trình diệt virus (Antivirus) thực tế.

✨ Tính năng chính

Hệ thống tích hợp 4 lớp bảo vệ chính:

1.  🔍 Quét Chữ Ký (Signature Scanning):
    - So khớp mã băm (Hash MD5/SHA256) với cơ sở dữ liệu mẫu nhận diện đã biết.
    - Tốc độ cực nhanh, phát hiện chính xác các malware cũ.

2.  🧠 Phân tích Heuristic (Static Heuristics):
    - Phân tích cấu trúc file PE (Portable Executable) mà không cần chạy file.
    - Phát hiện file bị nén/mã hóa (Packed) dựa trên độ hỗn loạn thông tin (Shannon Entropy).
    - Kiểm tra Import Table để tìm các API nguy hiểm (Injection, Keylogging).
    - Kiểm tra chữ ký số (Digital Signature).

3.  🔬 Phân tích Động (Dynamic Analysis / Sandbox):
    - Môi trường cô lập: Chạy file trong môi trường giả lập, tự động điều hướng file tạm.
    - Network Guard: Tự động tạo Firewall Rule chặn kết nối mạng của mẫu vật.
    - Giám sát toàn diện: Theo dõi hành vi tạo tiến trình con (Process Tree), thay đổi Registry (Persistence), và thao tác File System (Dropper).
    - Threat Scoring: Chấm điểm rủi ro (0-100) dựa trên hành vi thực tế.

4.  ☁️ Xác minh Đám mây (Cloud Intelligence):
    - Tích hợp VirusTotal API v3.
    - Đối chiếu kết quả với hơn 70 engine antivirus quốc tế để giảm thiểu báo động giả (False Positive).

5.  ⚙️ Các tính năng khác:
    - Giao diện đồ họa (GUI): Hiện đại, dễ sử dụng với Tkinter.
    - Quarantine: Cơ chế cách ly file an toàn.
    - Reporting: Xuất báo cáo chi tiết ra file văn bản.
    - Multithreading: Xử lý đa luồng giúp ứng dụng hoạt động mượt mà.

🛠️ Yêu cầu hệ thống

- Hệ điều hành: Windows 10/11 (Bắt buộc do sử dụng thư viện WMI và WinAPI).
- Ngôn ngữ: Python 3.8 trở lên.

🚀 Cài đặt

1.  Clone dự án:
    git clone [https://github.com/KhanhBaoLe/Detection-and-Remove-Trojan]
    

2.  Cài đặt thư viện phụ thuộc:
    pip install -r requirements.txt
    
    Nếu chưa có file `requirements.txt`, hãy cài thủ công các thư viện sau:
    pip install psutil pefile sqlalchemy wmi pywin32 requests yara-python
    

3.  Cấu hình API Key (Tùy chọn):
    - Để sử dụng tính năng quét VirusTotal, hãy mở file `config/api_keys.py`.
    - hay thế `YOUR_API_KEY_HERE` bằng API Key của bạn từ [VirusTotal](https://www.virustotal.com/).

📖 Hướng dẫn sử dụng

1.  Các chế độ quét:
    - Signature Scan: Quét nhanh dựa trên database.
    - Behaviour Scan: Quét tĩnh dựa trên các chuỗi/mẫu hành vi trong file binary.
    - Full Scan: Kết hợp cả Signature và Behaviour.
    - Dynamic Analysis: Chọn một file `.exe` cụ thể để chạy trong Sandbox và quan sát hành vi (mất khoảng 30s).
    - VirusTotal API: Quét hash file trên đám mây.

2. Xử lý mối đe dọa:
    Sau khi quét, nếu phát hiện mối đe dọa (Threat Score cao), nhấn nút "Remove Threats" để di chuyển file vào thư mục cách ly (`quarantine/`).
├── utils/                   # Các hàm tiện ích (Logger, Hash)
├── main.py                  # Entry point
└── requirements.txt         # Danh sách thư viện

