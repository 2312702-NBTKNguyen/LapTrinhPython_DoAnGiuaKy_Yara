# Kiến trúc hệ thống - YARA Malware Scanner

## Tổng quan

YARA Malware Scanner là hệ thống phát hiện mã độc sử dụng kết hợp hai phương pháp:

1. **Hash-based Detection**: So sánh SHA256 hash với database malware đã biết
2. **YARA Pattern Matching**: Quét file bằng YARA rules để phát hiện malware patterns

## Sơ đồ kiến trúc

```
┌─────────────────────────────────────────────────────────────────┐
│                         ĐIỂM VÀO                                │
│                           main.py                               │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      LỚP TRÌNH DIỆN                             │
│                      CLI Interface                              │
│                    (malware_scanner/cli.py)                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                       LỚP DỊCH VỤ                               │
│                  (malware_scanner/service.py)                    │
│                                                                 │
│  MalwareScanner class - Điều phối tất cả thao tác quét         │
└────────────────────────────┬────────────────────────────────────┘
                             │
           ┌─────────────────┼─────────────────┐
           ▼                 ▼                 ▼
┌──────────────────┐ ┌──────────────┐ ┌──────────────────┐
│   LỚP ENGINE     │ │  LỚP ARCHIVE │ │   LỚP MEMORY     │
│                  │ │              │ │   (Tương lai)    │
│ engine.py        │ │ archive.py   │ │ memory.py        │
│ - Tính hash      │ │ - Quét ZIP   │ │ - Quét process   │
│ - Quét YARA      │ │ - Quét 7z    │ │ - Memory dump    │
│ - Quét file      │ │ - Quét RAR   │ │                  │
└────────┬─────────┘ └──────────────┘ └──────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│                       LỚP DỮ LIỆU                               │
├─────────────────────────────┬───────────────────────────────────┤
│      Database               │         Reporting                 │
│     (db.py)                 │      (reporting.py)               │
│                             │                                   │
│ - Kết nối PostgreSQL        │ - Báo cáo terminal                │
│ - Tra cứu hash              │ - Xuất file (.txt)                │
│ - Lịch sử quét              │ - Xuất JSON                       │
│ - Malware signatures        │                                   │
└─────────────────────────────┴───────────────────────────────────┘
```

## Mô tả các module

### Core modules (`malware_scanner/`)

| Module          | Mô tả           | Trách nhiệm                       |
| --------------- | --------------- | --------------------------------- |
| `cli.py`        | CLI interface   | Tương tác người dùng, xử lý input |
| `service.py`    | Business logic  | Điều phối quét, workflow          |
| `engine.py`     | Engine quét     | Tính hash, quét YARA              |
| `archive.py`    | Hỗ trợ archive  | Quét ZIP/7z/RAR                   |
| `db.py`         | Lưu trữ dữ liệu | Thao tác PostgreSQL               |
| `reporting.py`  | Đầu ra          | Tạo báo cáo                       |
| `exceptions.py` | Xử lý lỗi       | Custom exception classes          |

### Luồng dữ liệu

```
Input người dùng (File/Thư mục/Archive)
    │
    ▼
Lớp Dịch vụ (MalwareScanner)
    │
    ├─► Tính Hashes
    │   └─► engine.calculate_file_hashes()
    │
    ├─► Kiểm tra Hash Database (Nhanh)
    │   └─► db.check_hash_in_db()
    │       ├─► KHỚP → Phát hiện HASH_MATCH
    │       └─► KHÔNG KHỚP → Chuyển sang YARA
    │
    ├─► Quét YARA Pattern (Sâu)
    │   └─► engine.scan_with_yara()
    │       ├─► KHỚP → Phát hiện YARA_MATCH
    │       └─► KHÔNG KHỚP → SẠCH
    │
    └─► Ghi log & Báo cáo
        ├─► db.log_scan_result()
        └─► reporting.print_summary()
```

## Luồng phát hiện

### Layer 1: Hash-based (Nhanh)

- Tính SHA256 hash của file
- Truy vấn PostgreSQL để tìm hash malware đã biết
- Thời gian tra cứu: O(1)
- Độ tin cậy: Cao (khớp chính xác)

### Layer 2: YARA pattern (Sâu)

- Compile YARA rules khi khởi động
- Quét nội dung file theo rules
- Pattern matching cho các malware signatures đã biết
- Có thể phát hiện variants và families

### Layer 3: Quét archive

- Extract contents của archive vào memory
- Quét từng file đã extract
- Hỗ trợ nested archives (với giới hạn depth)
- Không extract ra disk (bảo mật)

## Chiến lược xử lý lỗi

```
Exception Hierarchy:
    ScannerError (base)
    ├── DatabaseError
    │   ├── ConnectionError
    │   └── QueryError
    ├── YaraError
    │   ├── RuleCompilationError
    │   └── ScanError
    ├── ArchiveError
    │   ├── ExtractionError
    │   └── UnsupportedFormatError
    └── ConfigurationError
```

Tất cả lỗi được bắt ở service layer và ghi log đầy đủ.
