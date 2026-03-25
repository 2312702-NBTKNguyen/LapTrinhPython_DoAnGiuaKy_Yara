# Đặc tả tính năng - YARA Malware Scanner

## 1. Archive Scanning

### Mô tả

Quét malware bên trong file archive (ZIP, 7z, RAR) mà không cần extract ra disk.

### Yêu cầu chức năng

| ID     | Requirement                           | Priority |
| ------ | ------------------------------------- | -------- |
| ARC-01 | Hỗ trợ file ZIP                       | P0       |
| ARC-02 | Hỗ trợ file 7z                        | P0       |
| ARC-03 | Hỗ trợ file RAR                       | P1       |
| ARC-04 | Xử lý nested archives                 | P1       |
| ARC-05 | Giới hạn depth để tránh zip bomb      | P0       |
| ARC-06 | In-memory extraction (không ghi disk) | P0       |

### Chi tiết triển khai

**ZIP scanning:**

```python
# Sử dụng zipfile (stdlib)
import zipfile

with zipfile.ZipFile(archive_path) as zf:
    for info in zf.infolist():
        if not info.is_dir():
            data = zf.read(info.filename)  # Đọc vào memory
            matches = yara_rules.match(data=data)
```

**7z scanning:**

```python
# Sử dụng py7zr (third-party)
import py7zr

with py7zr.SevenZipFile(archive_path) as z:
    data = z.readall()
    for filename, buffer in data.items():
        matches = yara_rules.match(data=buffer.read())
```

### Cơ chế bảo vệ

1. **Phát hiện archive bomb:**
   - Giới hạn kích thước extract (mặc định: 100MB)
   - Giới hạn compression ratio (mặc định: 100:1)
   - Giới hạn số file (mặc định: 1000 files)

2. **Giới hạn nested archive:**
   - Độ sâu tối đa: 3 levels
   - Theo dõi archive đã truy cập để tránh cycles

### Xử lý lỗi

```python
class ArchiveError(ScannerError):
    """Exception base cho thao tác archive."""
    pass

class UnsupportedFormatError(ArchiveError):
    """Định dạng file không được hỗ trợ."""
    pass

class ExtractionError(ArchiveError):
    """Không thể extract archive."""
    pass

class ArchiveBombError(ArchiveError):
    """Phát hiện archive bomb tiềm ẩn."""
    pass
```

### Test cases

| Test      | Input                    | Kết quả mong đợi    |
| --------- | ------------------------ | ------------------- |
| TC-ARC-01 | ZIP với file sạch        | Kết quả CLEAN       |
| TC-ARC-02 | ZIP với malware pattern  | Kết quả YARA_MATCH  |
| TC-ARC-03 | Nested ZIP (2 levels)    | Quét cả hai levels  |
| TC-ARC-04 | Archive bomb (ratio lớn) | ArchiveBombError    |
| TC-ARC-05 | ZIP được bảo vệ password | Bỏ qua với cảnh báo |
| TC-ARC-06 | Archive bị hỏng          | ExtractionError     |

---

## 2. YARA Rules Enhancement

### Mô tả

Bổ sung các rule YARA generic để phát hiện các patterns phổ biến.

### Rule categories

Hiện tại các nhóm rule generic đang được gom trong file:

- `rules/core/pe_analyzer.yar` (được include bởi `rules/index.yar`)

#### 2.1 PE Analyzer (`rules/core/pe_analyzer.yar`)

Phát hiện các đặc điểm đáng ngờ trong file PE.

| Rule ID | Pattern               | Mô tả                        |
| ------- | --------------------- | ---------------------------- |
| PE-001  | High entropy sections | Code packed/encrypted        |
| PE-002  | Suspicious imports    | APIs nguy hiểm               |
| PE-003  | Anomalous timestamps  | Bất thường thời gian compile |
| PE-004  | Overlay detection     | Dữ liệu ẩn trong overlay     |

#### 2.2 Packer Detection (trong `pe_analyzer.yar`)

Phát hiện các packer/crypter phổ biến.

| Rule ID  | Packer    | Indicators               |
| -------- | --------- | ------------------------ |
| PACK-001 | UPX       | UPX sections, signatures |
| PACK-002 | Themida   | Themida markers          |
| PACK-003 | VMProtect | VMProtect patterns       |
| PACK-004 | ASPack    | ASPack signatures        |

#### 2.3 Crypto Detection (trong `pe_analyzer.yar`)

Phát hiện thư viện mã hóa (có thể dùng cho ransomware).

| Rule ID    | Library       | Patterns            |
| ---------- | ------------- | ------------------- |
| CRYPTO-001 | OpenSSL       | SSL/TLS strings     |
| CRYPTO-002 | Crypto++      | Crypto++ signatures |
| CRYPTO-003 | Custom crypto | S-box patterns      |

#### 2.4 Suspicious APIs (trong `pe_analyzer.yar`)

Phát hiện các API call đáng ngờ.

| Rule ID | Category          | APIs                               |
| ------- | ----------------- | ---------------------------------- |
| API-001 | Process injection | VirtualAllocEx, WriteProcessMemory |
| API-002 | Persistence       | RegSetValue, CreateService         |
| API-003 | Evasion           | NtQueryInformationProcess          |
| API-004 | Data exfil        | InternetOpen, HttpSendRequest      |

#### 2.5 Network Indicators (trong `pe_analyzer.yar`)

Phát hiện các patterns mạng đáng ngờ.

| Rule ID | Pattern        | Mô tả                        |
| ------- | -------------- | ---------------------------- |
| NET-001 | Hardcoded IPs  | Địa chỉ IP đáng ngờ          |
| NET-002 | DGA patterns   | Domain generation algorithms |
| NET-003 | Tor indicators | Tor exit nodes, .onion       |
| NET-004 | C2 patterns    | Command & control patterns   |

---

## 4. Xử lý lỗi

### Exception hierarchy

```python
ScannerError(Exception)
├── DatabaseError
│   ├── ConnectionError
│   ├── QueryError
│   └── SchemaError
├── YaraError
│   ├── RuleCompilationError
│   ├── RuleNotFoundError
│   └── ScanError
├── ArchiveError
│   ├── UnsupportedFormatError
│   ├── ExtractionError
│   ├── PasswordProtectedError
│   └── ArchiveBombError
├── ConfigurationError
│   ├── MissingConfigError
│   └── InvalidConfigError
└── PermissionError
    ├── InsufficientPrivilegesError
    └── AccessDeniedError
```

### Chiến lược xử lý lỗi

1. **Service layer** bắt tất cả exceptions
2. **Ghi log lỗi** với context đầy đủ
3. **Trả về kết quả lỗi** (không crash)
4. **Hiển thị thông báo thân thiện** với người dùng

```python
try:
    result = scanner.scan_target(filepath)
except YaraError as e:
    logger.error(f"Quét YARA thất bại: {e}")
    return ScanResult(error=str(e))
except Exception as e:
    logger.exception(f"Lỗi không mong muốn: {e}")
    return ScanResult(error="Lỗi nội bộ")
```

---

## 5. Cấu hình

### Biến môi trường

```bash
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=yara_malware_signatures
DB_USER=yara_user
DB_PASSWORD=yara_password

# MalwareBazaar API
MB_AUTH_KEY=your_api_key

# Scanner settings
MAX_ARCHIVE_SIZE_MB=100
MAX_EXTRACTION_RATIO=100
MAX_NESTED_DEPTH=3
MAX_FILES_PER_ARCHIVE=1000
```

### File cấu hình (tương lai)

```yaml
# config.yaml
scanner:
  rules_path: rules/index.yar
  max_workers: 4
  timeout: 30

archive:
  max_size_mb: 100
  max_ratio: 100
  max_depth: 3
  max_files: 1000
  formats:
    - zip
    - 7z
    - rar

database:
  pool_size: 5
  timeout: 10
```
