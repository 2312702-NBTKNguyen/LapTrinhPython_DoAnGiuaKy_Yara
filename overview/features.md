# Đặc tả tính năng - YARA Malware Scanner

## 1. Archive Scanning

### Mô tả
Quét malware bên trong file archive (ZIP, 7z, RAR) mà không cần extract ra disk.

### Yêu cầu chức năng

| ID | Requirement | Priority |
|----|-------------|----------|
| ARC-01 | Hỗ trợ file ZIP | P0 |
| ARC-02 | Hỗ trợ file 7z | P0 |
| ARC-03 | Hỗ trợ file RAR | P1 |
| ARC-04 | Xử lý nested archives | P1 |
| ARC-05 | Giới hạn depth để tránh zip bomb | P0 |
| ARC-06 | In-memory extraction (không ghi disk) | P0 |

### Chi tiết triển khai

**ZIP scanning:**
```python
# Sử dụng zipfile (stdlib)
import zipfile

with zipfile.ZipFile(archive_path) as zf:
    for info in zf.infolist():
        if not info.is_dir():
            data = zf.read(info.filename)  # Read to memory
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

### Protection mechanisms

1. **Archive bomb detection:**
   - Giới hạn extraction size (default: 100MB)
   - Giới hạn compression ratio (default: 100:1)
   - Giới hạn số file (default: 1000 files)

2. **Nested archive limit:**
   - Max depth: 3 levels
   - Track visited archives to prevent cycles

### Error handling

```python
class ArchiveError(ScannerError):
    """Base exception for archive operations."""
    pass

class UnsupportedFormatError(ArchiveError):
    """File format not supported."""
    pass

class ExtractionError(ArchiveError):
    """Failed to extract archive."""
    pass

class ArchiveBombError(ArchiveError):
    """Potential archive bomb detected."""
    pass
```

### Test cases

| Test | Input | Expected |
|------|-------|----------|
| TC-ARC-01 | ZIP with clean file | CLEAN result |
| TC-ARC-02 | ZIP with malware pattern | YARA_MATCH result |
| TC-ARC-03 | Nested ZIP (2 levels) | Scan both levels |
| TC-ARC-04 | Archive bomb (huge ratio) | ArchiveBombError |
| TC-ARC-05 | Password-protected ZIP | Skip with warning |
| TC-ARC-06 | Corrupted archive | ExtractionError |

---

## 2. YARA Rules Enhancement

### Mô tả
Bổ sung các rule YARA generic để phát hiện các patterns phổ biến.

### Rule categories

#### 2.1 PE Analyzer (`pe_analyzer.yar`)
Phát hiện các đặc điểm đáng ngờ trong file PE.

| Rule ID | Pattern | Description |
|---------|---------|-------------|
| PE-001 | High entropy sections | Packed/encrypted code |
| PE-002 | Suspicious imports | Dangerous APIs |
| PE-003 | Anomalous timestamps | Compilation time anomalies |
| PE-004 | Overlay detection | Hidden data in overlay |

#### 2.2 Packer Detection (`packer_detection.yar`)
Phát hiện các packer/crypter phổ biến.

| Rule ID | Packer | Indicators |
|---------|--------|------------|
| PACK-001 | UPX | UPX sections, signatures |
| PACK-002 | Themida | Themida markers |
| PACK-003 | VMProtect | VMProtect patterns |
| PACK-004 | ASPack | ASPack signatures |

#### 2.3 Crypto Detection (`crypto_detection.yar`)
Phát hiện thư viện mã hóa (có thể dùng cho ransomware).

| Rule ID | Library | Patterns |
|---------|---------|----------|
| CRYPTO-001 | OpenSSL | SSL/TLS strings |
| CRYPTO-002 | Crypto++ | Crypto++ signatures |
| CRYPTO-003 | Custom crypto | S-box patterns |

#### 2.4 Suspicious APIs (`suspicious_apis.yar`)
Phát hiện các API call đáng ngờ.

| Rule ID | Category | APIs |
|---------|----------|------|
| API-001 | Process injection | VirtualAllocEx, WriteProcessMemory |
| API-002 | Persistence | RegSetValue, CreateService |
| API-003 | Evasion | NtQueryInformationProcess |
| API-004 | Data exfil | InternetOpen, HttpSendRequest |

#### 2.5 Network Indicators (`network_indicators.yar`)
Phát hiện các patterns mạng đáng ngờ.

| Rule ID | Pattern | Description |
|---------|---------|-------------|
| NET-001 | Hardcoded IPs | Suspicious IP addresses |
| NET-002 | DGA patterns | Domain generation algorithms |
| NET-003 | Tor indicators | Tor exit nodes, .onion |
| NET-004 | C2 patterns | Command & control patterns |

---

## 4. Error Handling

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

### Error handling strategy

1. **Service layer** catches all exceptions
2. **Log error** with context
3. **Return error result** (don't crash)
4. **Display user-friendly message**

```python
try:
    result = scanner.scan_target(filepath)
except YaraError as e:
    logger.error(f"YARA scan failed: {e}")
    return ScanResult(error=str(e))
except Exception as e:
    logger.exception(f"Unexpected error: {e}")
    return ScanResult(error="Internal error")
```

---

## 5. Configuration

### Environment variables

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

### Config file (future)

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
