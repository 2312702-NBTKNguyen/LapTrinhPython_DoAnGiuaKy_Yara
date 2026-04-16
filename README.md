# ỨNG DỤNG THƯ VIỆN YARA TRONG PHÁT HIỆN MÃ ĐỘC

**Học phần:** Lập trình Python

**Sinh viên thực hiện:** Nguyễn Bá Thiều Khôi Nguyên - Hồ Quốc Long

## 1) Mô tả chương trình

Đây là ứng dụng quét mã độc viết bằng Python, kết hợp:

- Các tập luật YARA để nhận diện hành vi/chữ ký mã độc trong file.
- Đối chiếu mã băm (MD5/SHA1/SHA256/SHA3-384) với dữ liệu signature.
- Giao diện desktop để thao tác quét file/thư mục, xem log, kết quả và lịch sử.
- Tích hợp CSDL để lưu trữ dữ liệu signature và lịch sử quét.

### Chức năng chính

- Quét 1 file hoặc cả thư mục.
- Phát hiện bằng 2 lớp:
  - Hash Match: so khớp mã băm với dữ liệu signature đã đồng bộ.
  - YARA Match: so khớp theo luật YARA trong thư mục rules.
- Hiển thị kết quả theo từng file (phát hiện / sạch / lỗi).
- Lưu báo cáo quét vào thư mục logs.
- Đồng bộ signatures từ MalwareBazaar thông qua API.

## 2) Yêu cầu môi trường

- Hệ điều hành: Linux/Windows/macOS
- Python: khuyến nghị 3.11+
- pip và virtual environment

## 3) Hướng dẫn chạy từng bước

### Bước 1: Clone mã nguồn

```bash
git clone https://github.com/2312702-NBTKNguyen/10_Yara_Python.git
cd LapTrinhPython_DoAnGiuaKy_Yara
```

### Bước 2: Tạo và kích hoạt môi trường ảo

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows (PowerShell):

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Bước 3: Cài đặt các thư viện cần thiết 

```bash
pip install -r requirements.txt
```

### Bước 4: Tạo file .env

Tạo file .env ở thư mục gốc dự án dựa trên `.env.example` và điền các giá trị phù hợp.

Lưu ý:

- Nếu chưa có MB_AUTH_KEY vẫn có thể quét được bằng luật YARA.
- Chức năng đồng bộ signatures từ MalwareBazaar sẽ báo lỗi nếu thiếu key.

### Bước 5: Chạy ứng dụng

```bash
python main.py
```

### Bước 6: Thao tác trên giao diện

1. Chọn file hoặc thư mục cần quét.
2. (Tùy chọn) Nhấn "Đồng bộ signatures" để cập nhật dữ liệu mã băm từ MalwareBazaar.
3. Nhấn "Quét" để bắt đầu.
4. Theo dõi:
   - Kết quả ở bảng Results.
   - Nhật ký ở Log panel.
   - Lịch sử ở History panel.
5. Nhấn "Xuất báo cáo" để mở báo cáo trong thư mục logs sau khi quét xong.

## 4) Cấu trúc dự án

```text
LapTrinhPython_DoAnGiuaKy_Yara/
|-- config.py                      # Cấu hình ứng dụng, đọc biến môi trường
|-- main.py                        # Điểm vào chương trình
|-- requirements.txt               # Danh sách thư viện Python
|-- pyproject.toml
|-- README.md
|
|-- data/
|   `-- malware_signatures.json    # Dữ liệu signatures sau khi đồng bộ
|
|-- data_tools/
|   |-- __init__.py
|   |-- data_loader.py             # Khởi tạo dữ liệu signatures vào CSDL
|   `-- db_setup.py                # Kết nối CSDL, khởi tạo schema
|
|-- database/
|   `-- create_schema.sql          # Schema SQLite
|
|-- gui/
|   |-- __init__.py
|   |-- main_window.py             # Giao diện chính
|   `-- components/
|       |-- __init__.py
|       |-- history_panel.py       # Panel lịch sử quét
|       |-- log_panel.py           # Panel log runtime
|       `-- results_panel.py       # Panel kết quả quét
|
|-- malware_scanner/
|   |-- exceptions.py
|   |-- reporting.py               # Sinh file báo cáo quét
|   |-- scanner.py                 # Engine quét chính
|   `-- detection/
|       |-- anti_evasion.py        # Hỗ trợ xử lý biến thể mã độc dùng kỹ thuật né tránh
|       |-- hashing.py             # Tính hash file
|       `-- yara_engine.py         # Tải/áp dụng luật YARA
|
|-- rules/
|   |-- index.yar                  # Điểm vào các luật
|   |-- core/                      # Nhóm luật lõi
|   `-- malware_families/          # Luật theo từng họ mã độc
|
|-- logs/                          # Kết quả báo cáo sau mỗi lần quét
`-- slides/                        # Slide thuyết trình
```

## 5) Ghi chú vận hành

- Nếu chưa có database/scanner.db, hệ thống sẽ tự tạo khi chạy lần đầu.
- Nếu đường dẫn các tập luật thay đổi, cập nhật YARA_RULES_PATH trong .env.
- Với file lớn hoặc nhiều file, thời gian quét phụ thuộc CPU và I/O.
