# YARA Malware Scanner

Hệ thống phát hiện mã độc sử dụng kết hợp hai phương pháp: Hash-based Detection và YARA Pattern Matching.

## Tính năng chính

- **Quét file bằng YARA rules**: Phát hiện malware patterns trong file
- **Kiểm tra hash database**: So sánh SHA256 hash với database malware đã biết
- **Quét archive**: Hỗ trợ quét malware bên trong file ZIP và 7z mà không cần extract
- **Báo cáo chi tiết**: Xuất báo cáo ra terminal và file .txt
- **14 malware families**: YARA rules cho các họ malware phổ biến

## Cài đặt

### Yêu cầu

- Python 3.8+
- PostgreSQL 12+
- pip

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

Tạo file `.env` với các thông tin database:

```bash
DB_HOST=localhost
DB_PORT=5432
DB_NAME=yara_malware_signatures
DB_USER=postgres
DB_PASSWORD=your_password
```

### Bước 4: Khởi tạo database

```bash
psql -U postgres -f database/01_create_database.sql
psql -U postgres -d yara_malware_signatures -f database/02_create_tables.sql
```

### Bước 5: Import dữ liệu malware signatures

```bash
python scripts/get_malware_data.py
python scripts/malware_data_filter.py
python scripts/import_data.py

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
python main.py --interactive

# Quét ngầm một file/thư mục rồi thoát
python main.py --scan /path/to/file_or_folder
```

### Quét file hoặc thư mục

```bash
# Nhập đường dẫn file hoặc thư mục
/home/user/malware_sample.exe
/home/user/downloads
```

### Xem báo cáo

Báo cáo sẽ được hiển thị trên terminal và lưu vào thư mục `logs/`.

## Cấu trúc dự án

```
├── malware_scanner/        # Core package
│   ├── cli.py              # CLI interface
│   ├── service.py          # Business logic
│   ├── engine.py           # YARA scanning engine
│   ├── archive.py          # Archive scanning
│   ├── db.py               # PostgreSQL operations
│   ├── reporting.py        # Report generation
│   └── exceptions.py       # Custom exceptions
├── rules/                  # YARA rules
│   ├── index.yar           # Master rule file
│   └── families/           # Malware family rules
├── tests/                  # Test files
├── database/               # Database setup scripts
├── scripts/                # Data + workflow scripts
│   └── workflows.py        # Nghiệp vụ update/scan/interactive
├── main.py                 # CLI entry point chính
└── scanner.py              # Wrapper tương thích lệnh cũ
```

## Phát hiện malware

### Layer 1: Hash-based Detection

- Tính SHA256 hash của file
- Kiểm tra trong PostgreSQL database
- Thời gian: O(1)
- Độ tin cậy: Cao (khớp chính xác)

### Layer 2: YARA Pattern Matching

- Compile YARA rules vào RAM
- Quét file bằng pattern matching
- Phát hiện malware variants và families
- Thời gian: Tùy thuộc kích thước file

### Layer 3: Archive Scanning

- Extract archive contents vào memory
- Quét từng file bên trong archive
- Hỗ trợ nested archives (giới hạn depth)
- Không extract ra disk (bảo mật)

## Malware families (14)

- **Info Stealers**: RedLineStealer, LokiBot, AgentTesla, Formbook
- **Banking Trojans**: Emotet, TrickBot, Mirai, Dridex
- **Ransomware**: WannaCry, LockBit, Conti, Ryuk
- **RATs**: RemcosRAT, njRAT

## Testing

Chạy test suite:

```bash
python tests/test_archive.py
```
