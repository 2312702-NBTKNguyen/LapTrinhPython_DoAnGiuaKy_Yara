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
- **Báo cáo chi tiết**: Xuất báo cáo ra terminal và file .txt

## Khởi chạy nhanh

```bash
# 1) Cài dependencies
pip install -r requirements.txt

# 2) Tạo file .env (DB + MB_AUTH_KEY)

# 3) Khởi tạo lần đầu
python main.py --run

# 4) Mở GUI CustomTkinter (Windows-first)
python main.py
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
# Khởi chạy (setup DB + fetch + filter + import)
python main.py --run
```

## Cách sử dụng

### Chạy chương trình

```bash
# Mở GUI (mặc định)
python main.py

# Khởi chạy và làm mới dữ liệu signatures
python main.py --run

# Quét bằng CLI (legacy)
python main.py --scan /path/to/file_or_folder

# Xem trợ giúp
python main.py -h
```

Lưu ý:

- GUI CustomTkinter là chế độ sử dụng chính.
- Dự án ưu tiên vận hành trên Windows; Linux hiện hỗ trợ ở mức tương thích cơ bản.

### Quét file hoặc thư mục

Trong GUI:

- Bấm `File` hoặc `Folder` để chọn target.
- Bấm `Start` để bắt đầu quét.
- Bấm `Cancel` để yêu cầu dừng quét.
- Tab `Results` hiển thị kết quả realtime; tab `History` hiển thị lịch sử từ database.

## Báo cáo kết quả

Báo cáo được tạo theo 2 dạng:

- Terminal summary ngay sau khi quét.
- File báo cáo .txt trong thư mục logs/.

Trong GUI, có thể bấm `Open Report` để mở nhanh file báo cáo mới nhất.

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

Hệ thống sử dụng chuỗi phát hiện theo thứ tự: hash database -> YARA pattern matching.

Chi tiết triển khai được mô tả trong overview/architecture.md và overview/features.md.

## Các họ Malware (14)

- **Info Stealers**: RedLineStealer, LokiBot, AgentTesla, Formbook
- **Banking Trojans**: Emotet, TrickBot, Mirai, Dridex
- **Ransomware**: WannaCry, LockBit, Conti, Ryuk
- **RATs**: RemcosRAT, njRAT

## Lỗi thường gặp

### 1. Thiếu kết nối database

Kiểm tra lại các biến DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD trong .env.

### 2. Không có MB_AUTH_KEY

Lỗi thường gặp khi chạy --run.

Thêm MB_AUTH_KEY vào .env rồi chạy lại.

### 3. Không thấy file report

Kiểm tra thư mục logs/ và quyền ghi file tại thư mục dự án.

## Testing

Chạy test suite:

```bash
pytest tests/test_scan_flow.py
```

Chạy toàn bộ thư mục tests:

```bash
pytest tests
```
