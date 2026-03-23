# Kiến trúc hệ thống - YARA Malware Scanner

## Tổng quan

YARA Malware Scanner là hệ thống phát hiện mã độc sử dụng kết hợp hai phương pháp:
1. **Hash-based Detection**: So sánh SHA256 hash với database malware đã biết
2. **YARA Pattern Matching**: Quét file bằng YARA rules để phát hiện malware patterns

## Sơ đồ kiến trúc

```
┌─────────────────────────────────────────────────────────────────┐
│                         ENTRY POINT                             │
│                          scanner.py                             │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      PRESENTATION LAYER                         │
│                      CLI Interface                              │
│                    (malware_scanner/cli.py)                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                       SERVICE LAYER                             │
│                  (malware_scanner/service.py)                    │
│                                                                 │
│  MalwareScanner class - Orchestrates all scanning operations   │
└────────────────────────────┬────────────────────────────────────┘
                             │
           ┌─────────────────┼─────────────────┐
           ▼                 ▼                 ▼
┌──────────────────┐ ┌──────────────┐ ┌──────────────────┐
│   ENGINE LAYER   │ │  ARCHIVE     │ │   MEMORY LAYER   │
│                  │ │  LAYER       │ │   (Future)       │
│ engine.py        │ │ archive.py   │ │ memory.py        │
│ - Hash calc      │ │ - ZIP scan   │ │ - Process scan   │
│ - YARA scan      │ │ - 7z scan    │ │ - Memory dump    │
│ - File scan      │ │ - RAR scan   │ │                  │
└────────┬─────────┘ └──────────────┘ └──────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│                       DATA LAYER                                │
├─────────────────────────────┬───────────────────────────────────┤
│      Database               │         Reporting                 │
│     (db.py)                 │      (reporting.py)               │
│                             │                                   │
│ - PostgreSQL connection     │ - Terminal report                 │
│ - Hash lookup               │ - File export (.txt)              │
│ - Scan history              │ - JSON export                     │
│ - Malware signatures        │                                   │
└─────────────────────────────┴───────────────────────────────────┘
```

## Module descriptions

### Core modules (`malware_scanner/`)

| Module | Purpose | Responsibilities |
|--------|---------|------------------|
| `cli.py` | CLI interface | User interaction, input handling |
| `service.py` | Business logic | Scan orchestration, workflow |
| `engine.py` | Scanning engine | Hash calculation, YARA scanning |
| `archive.py` | Archive support | ZIP/7z/RAR scanning |
| `db.py` | Data persistence | PostgreSQL operations |
| `reporting.py` | Output | Report generation |
| `exceptions.py` | Error handling | Custom exception classes |
| `config.py` | Configuration | Settings management |

### Data flow

```
User Input (File/Directory/Archive)
    │
    ▼
Service Layer (MalwareScanner)
    │
    ├─► Calculate Hashes
    │   └─► engine.calculate_file_hashes()
    │
    ├─► Hash Database Check (Fast Path)
    │   └─► db.check_hash_in_db()
    │       ├─► MATCH → HASH_MATCH detection
    │       └─► NO MATCH → Continue to YARA
    │
    ├─► YARA Pattern Scan (Deep Path)
    │   └─► engine.scan_with_yara()
    │       ├─► MATCH → YARA_MATCH detection
    │       └─► NO MATCH → CLEAN
    │
    └─► Log & Report
        ├─► db.log_scan_result()
        └─► reporting.print_summary()
```

## Detection flow

### Layer 1: Hash-based (Fast)
- Calculate SHA256 hash of file
- Query PostgreSQL for known malware hashes
- O(1) lookup time
- High confidence (exact match)

### Layer 2: YARA pattern (Deep)
- Compile YARA rules at startup
- Scan file content against rules
- Pattern matching for known malware signatures
- Can detect variants and families

### Layer 3: Archive scanning
- Extract archive contents to memory
- Scan each extracted file
- Support nested archives (with depth limit)
- No disk extraction (security)

## Error handling strategy

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

All errors are caught at service layer and logged appropriately.
