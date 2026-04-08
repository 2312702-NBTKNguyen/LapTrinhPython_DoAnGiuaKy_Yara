# YARA Malware Scanner

Hệ thống phát hiện mã độc sử dụng kết hợp hai phương pháp: Hash-based Detection và YARA Pattern Matching.

## Mục lục nhanh

- [Tính năng chính](#tính-năng-chính)
- [Khởi chạy nhanh](#khởi-chạy-nhanh)
- [Cài đặt chi tiết](#cài-đặt-chi-tiết)
- [Cách sử dụng](#cách-sử-dụng)
- [Báo cáo kết quả](#báo-cáo-kết-quả)
- [Lỗi thường gặp](#lỗi-thường-gặp)
- [Testing](#testing)

## Tính năng chính

- **Quét file bằng YARA rules**: Phát hiện malware patterns trong file
- **Kiểm tra hash database**: So sánh SHA256 hash với database malware đã biết
- **Quét archive**: Hỗ trợ quét malware bên trong file ZIP và RAR mà không cần extract
- **Báo cáo chi tiết**: Xuất báo cáo ra terminal và file .txt

## Khởi chạy nhanh

```bash
# 1) Cài dependencies
pip install -r requirements.txt

# 2) Tạo file .env (DB + MB_AUTH_KEY)

# 3) Khởi tạo lần đầu
python main.py --run

# 4) Cập nhật dữ liệu signatures ở các lần sau
python main.py --update

# 5) Quét thủ công (chương trình sẽ hỏi đường dẫn)
python main.py --scan
```

## Cài đặt chi tiết

### Yêu cầu

- Python 3.8+
- PostgreSQL 12+

### Bước 1: Clone repository

```bash
git clone https://github.com/2312702-NBTKNguyen/LapTrinhPython_DoAnGiuaKy_Yara.git
cd LapTrinhPython_DoAnGiuaKy_Yara
```

### Bước 2: Cài đặt dependencies

```bash
pip install -r requirements.txt
```

### Bước 3: Cấu hình database

Dựa vào file .env.example, tạo file .env với các thông tin database:

```bash
DB_HOST=your_host_here
DB_PORT=your_port_here
DB_NAME=your_database_name_here
DB_USER=your_username_here
DB_PASSWORD=your_password_here
```

Ví dụ:

```bash
DB_HOST=localhost
DB_PORT=5432
DB_NAME=yara_malware_signatures
DB_USER=postgres
DB_PASSWORD=your_password_
```

### Cấu hình tool giải nén RAR (Windows)

Nếu gặp lỗi Cannot find working tool khi quét .rar, thêm biến sau vào file .env:

```bash
RAR_TOOL_PATH=C:\\Program Files\\WinRAR\\UnRAR.exe
```

Hoặc dùng 7-Zip:

```bash
RAR_TOOL_PATH=C:\\Program Files\\7-Zip\\7z.exe
```

### Bước 4: Lấy và cấu hình MalwareBazaar API key

1. Đăng ký/đăng nhập tài khoản tại [MalwareBazaar](https://bazaar.abuse.ch/).
2. Tạo API key trong phần quản lý tài khoản.
3. Mở file .env và điền giá trị vào biến MB_AUTH_KEY.

Ví dụ:

```bash
MB_AUTH_KEY=your_malwarebazaar_api_key_here
```

### Bước 5: Khởi tạo database

```bash
psql -U postgres -f database/01_create_database.sql
psql -U postgres -d yara_malware_signatures -f database/02_create_tables.sql
```

### Bước 6: Import dữ liệu malware signatures

```bash
# Khởi chạy lần đầu (setup DB + fetch + filter + import)
python main.py --run

# Các lần sau chỉ cập nhật dữ liệu signatures
python main.py --update
```

## Cách sử dụng

### Chạy chương trình

```bash
# Khởi chạy lần đầu
python main.py --run

# Cập nhật dữ liệu signatures
python main.py --update

# Quét (nhập đường dẫn khi chương trình yêu cầu)
python main.py --scan

# Xem trợ giúp
python main.py -h
```

### Quét file hoặc thư mục

```bash
# Nhập đường dẫn file hoặc thư mục
/home/user/malware_sample.exe
/home/user/downloads
...
```

Gợi ý:

- Có thể nhập đường dẫn có dấu ngoặc kép hoặc không.
- Nên quét thư mục mẫu trước khi quét toàn bộ hệ thống.
- Với file nén lớn hoặc nested sâu, thời gian quét sẽ tăng đáng kể.

## Báo cáo kết quả

Báo cáo được tạo theo 2 dạng:

- Terminal summary ngay sau khi quét.
- File báo cáo .txt trong thư mục logs/.

Ví dụ file:

- logs/scan_report_YYYYMMDD_HHMMSS.txt

Nội dung chính gồm:

- Số file đã quét, số phát hiện bằng hash/YARA, số file clean.
- Danh sách file bị phát hiện và signature tương ứng.
- Thời điểm quét để dễ đối chiếu lịch sử.

## Tài liệu kiến trúc và cấu trúc

- Cấu trúc thư mục chuẩn: overview/file-structure.md
- Kiến trúc hệ thống và luồng dữ liệu: overview/architecture.md
- Đặc tả tính năng: overview/features.md

## Cách phát hiện malware

Hệ thống sử dụng chuỗi phát hiện theo thứ tự: hash database -> YARA pattern matching -> archive scanning in-memory.

Chi tiết triển khai, giới hạn bảo vệ archive, và quy tắc xử lý lỗi được mô tả trong overview/architecture.md và overview/features.md.

## Các họ Malware (14)

- **Info Stealers**: RedLineStealer, LokiBot, AgentTesla, Formbook
- **Banking Trojans**: Emotet, TrickBot, Mirai, Dridex
- **Ransomware**: WannaCry, LockBit, Conti, Ryuk
- **RATs**: RemcosRAT, njRAT

## Lỗi thường gặp

### 1. Thiếu kết nối database

Kiểm tra lại các biến DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD trong .env.

### 2. Không có MB_AUTH_KEY

Lỗi thường gặp khi chạy --run hoặc --update.

Thêm MB_AUTH_KEY vào .env rồi chạy lại.

### 3. Không quét được RAR

Trên Windows, cấu hình RAR_TOOL_PATH trỏ đúng tới UnRAR.exe hoặc 7z.exe.

### 4. Không thấy file report

Kiểm tra thư mục logs/ và quyền ghi file tại thư mục dự án.

## Testing

Chạy test suite:

```bash
pytest
```

Chạy nhanh nhóm test lõi:

```bash
pytest tests/unit/test_service_flow.py tests/unit/test_archive_validation.py
```
