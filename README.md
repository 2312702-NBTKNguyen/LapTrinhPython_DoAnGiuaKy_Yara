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
- **Báo cáo chi tiết**: Xuất báo cáo ra file .txt và mở nhanh từ GUI

## Khởi chạy nhanh

```bash
# 1) Cài uv
# Linux/macOS:
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell):
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# 2) Tạo môi trường + cài dependencies
uv sync --extra dev

# 3) Tạo file .env (DB + MB_AUTH_KEY)

# 4) Mở GUI CustomTkinter (Windows-first)
uv run python main.py
```

## Cài đặt chi tiết

### Yêu cầu

- Python 3.8+
- SQLite (tích hợp sẵn trong Python sqlite3)

### Bước 1: Clone repository

```bash
git clone https://github.com/2312702-NBTKNguyen/LapTrinhPython_DoAnGiuaKy_Yara.git
cd LapTrinhPython_DoAnGiuaKy_Yara
```

### Bước 2: Cài đặt dependencies

#### Cách khuyến nghị: dùng uv

```bash
uv sync --extra dev
```

#### Cách tương thích cũ: dùng pip

```bash
pip install -r requirements.txt
```

Lưu ý: dependencies chính đã được quản lý qua `pyproject.toml` để dùng với uv.

### Bước 3: Cấu hình database

Dựa vào file .env.example, tạo file .env với các thông tin database:

```bash
DB_FILE=data/scanner.db
DB_TIMEOUT_SECONDS=30
DB_BUSY_TIMEOUT_MS=5000
```

Ví dụ:

```bash
DB_FILE=data/scanner.db
DB_TIMEOUT_SECONDS=30
DB_BUSY_TIMEOUT_MS=5000
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
uv run python main.py
```

Khi khởi động, ứng dụng sẽ tự tạo file SQLite và schema nếu chưa tồn tại.

### Bước 6: Import dữ liệu malware signatures

Trong GUI, bấm nút `Đồng bộ signatures` để đồng bộ signatures vào cơ sở dữ liệu.

## Cách sử dụng

### Chạy chương trình

```bash
# Mở GUI (chế độ hiện tại)
uv run python main.py
```

Lưu ý:

- GUI CustomTkinter là chế độ sử dụng chính.
- Các cờ CLI cũ (`--run`, `--scan`) hiện không còn được hỗ trợ trong entrypoint hiện tại.
- Dự án ưu tiên vận hành trên Windows; Linux hiện hỗ trợ ở mức tương thích cơ bản.

### Quét file hoặc thư mục

Trong GUI:

- Bấm `File` hoặc `Folder` để chọn target.
- Bấm `Start` để bắt đầu quét.
- Bấm `Cancel` để yêu cầu dừng quét.
- Tab `Results` hiển thị kết quả realtime; tab `History` hiển thị lịch sử từ database.

## Báo cáo kết quả

Báo cáo được tạo theo 2 dạng:

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

## Quy ước xử lý lỗi

- Core layer (data_tools, malware_scanner) ưu tiên raise exception thay vì vừa log lỗi vừa raise cho cùng một sự cố.
- GUI/entrypoint là boundary hiển thị lỗi cho người dùng qua log panel hoặc messagebox.
- Exception message cần đủ ngữ cảnh để GUI có thể hiển thị trực tiếp mà không cần log lỗi lặp lại ở core.

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

Kiểm tra lại biến DB_FILE trong .env và quyền ghi tại thư mục chứa file database.

### 2. Không có MB_AUTH_KEY

Lỗi thường gặp khi bấm `Đồng bộ signatures` trong GUI.

Thêm MB_AUTH_KEY vào .env rồi chạy lại.

### 3. Không thấy file report

Kiểm tra thư mục logs/ và quyền ghi file tại thư mục dự án.

## Testing

Chạy test suite:

```bash
uv run pytest tests/test_scan_flow.py
```

Chạy toàn bộ thư mục tests:

```bash
uv run pytest tests
```

## Quản lý dependencies bằng uv

Một số lệnh thường dùng:

```bash
# Đồng bộ môi trường theo pyproject.toml
uv sync --extra dev

# Chạy lệnh trong môi trường của dự án
uv run python main.py
uv run pytest tests

# Thêm dependency runtime
uv add <package-name>

# Thêm dependency cho nhóm dev
uv add --optional dev <package-name>
```

Nếu vẫn muốn giữ workflow cũ, bạn có thể tiếp tục dùng `pip install -r requirements.txt`.
