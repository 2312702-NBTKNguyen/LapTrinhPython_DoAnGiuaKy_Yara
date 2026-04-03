# YARA Malware Scanner

Hệ thống phát hiện mã độc sử dụng kết hợp hai phương pháp: Hash-based Detection và YARA Pattern Matching.

## Tính năng chính

- **Quét file bằng YARA rules**: Phát hiện malware patterns trong file
- **Kiểm tra hash database**: So sánh SHA256 hash với database malware đã biết
- **Quét archive**: Hỗ trợ quét malware bên trong file ZIP và RAR mà không cần extract
- **Báo cáo chi tiết**: Xuất báo cáo ra terminal và file .txt

## Cài đặt

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

Dựa vào file `.env.example`, tạo file `.env` với các thông tin database:

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

Nếu gặp lỗi `Cannot find working tool` khi quét `.rar`, thêm biến sau vào file `.env`:

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
3. Mở file `.env` và điền giá trị vào biến `MB_AUTH_KEY`.

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
python main.py --run
python main.py --update
python main.py --scan

# Quét ngầm một file/thư mục rồi thoát
python main.py --scan /path/to/file_or_folder
```

### Quét file hoặc thư mục

```bash
# Nhập đường dẫn file hoặc thư mục
/home/user/malware_sample.exe
/home/user/downloads
...
```

### Xem báo cáo

Báo cáo sẽ được hiển thị trên terminal và lưu vào thư mục `logs/`.

## Tài liệu kiến trúc và cấu trúc

- Cấu trúc thư mục chuẩn: `overview/file-structure.md`
- Kiến trúc hệ thống và luồng dữ liệu: `overview/architecture.md`
- Đặc tả tính năng: `overview/features.md`

## Cách phát hiện malware

Hệ thống sử dụng chuỗi phát hiện theo thứ tự: hash database -> YARA pattern matching -> archive scanning in-memory.

Chi tiết triển khai, giới hạn bảo vệ archive, và quy tắc xử lý lỗi được mô tả trong `overview/architecture.md` và `overview/features.md`.

## Các họ Malware (14)

- **Info Stealers**: RedLineStealer, LokiBot, AgentTesla, Formbook
- **Banking Trojans**: Emotet, TrickBot, Mirai, Dridex
- **Ransomware**: WannaCry, LockBit, Conti, Ryuk
- **RATs**: RemcosRAT, njRAT

## Testing

Chạy test suite:

```bash
pytest
```
