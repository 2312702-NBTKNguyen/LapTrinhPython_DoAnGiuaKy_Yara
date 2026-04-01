# Cấu trúc thư mục - YARA Malware Scanner

## Tổng quan

```
LapTrinhPython_DoAnGiuaKy_Yara/
├── overview/                    # Documentation
│   ├── architecture.md         # Kiến trúc hệ thống
│   ├── file-structure.md       # File này
│   ├── features.md             # Đặc tả tính năng
│   └── contributing.md         # Hướng dẫn đóng góp
│
├── malware_scanner/            # Core package
│   ├── __init__.py
│   ├── service.py              # Business logic (MalwareScanner class)
│   ├── engine.py               # Compatibility facade (legacy imports)
│   ├── detection/              # Detection internals
│   │   ├── hashing.py          # File hash calculation
│   │   ├── scan_variants.py    # Content variant extraction for YARA
│   │   └── yara_engine.py      # YARA compile and scanning APIs
│   ├── archive/                # Archive package
│   │   ├── __init__.py         # Archive facade exports
│   │   ├── scanner.py          # ArchiveScanner class
│   │   ├── types.py            # ArchiveScanResult dataclass
│   │   ├── zip_backend.py      # ZIP scanning backend
│   │   ├── sevenz_backend.py   # 7z scanning backend
│   │   └── rar_backend.py      # RAR scanning backend
│   ├── db.py                   # PostgreSQL operations
│   ├── reporting.py            # Report generation (TXT, JSON, CSV)
│   └── exceptions.py           # Custom exceptions
│
├── rules/                      # YARA rules
│   ├── index.yar               # Master rule file (includes all)
│   ├── core/                   # Generic detection rules
│   │   └── pe_analyzer.yar     # PE file analysis
│   └── malware_families/       # Malware family rules
│       ├── emotet.yar
│       ├── wannacry.yar
│       ├── lockbit.yar
│       └── ... (14 families)
│
│
├── tests/                      # Test files
│   ├── test_archive.py         # Archive scanning tests
│   ├── test_rule_coverage.py   # Rule coverage regression tests
│   └── samples/                # Test samples
│       ├── archives/
│       ├── test_emotet.txt
│       ├── test_wannacry.txt
│       └── test_lockbit.txt
│
├── database/                   # Database setup
│   ├── 01_create_database.sql
│   └── 02_create_tables.sql
│
├── scripts/                    # Data + workflow scripts
│   ├── data_sources.py
│   ├── db_setup.py
│   ├── pipeline.py
│   ├── utils.py
│   └── workflows.py
│
├── logs/                       # Scan reports (generated at runtime)
│   └── scan_report_*.txt/json/csv
│
├── main.py                     # Entry point
├── pyproject.toml              # Project metadata & uv dependencies
├── requirements.txt            # Python dependencies (pip)
├── .env                        # Environment variables (not in git)
├── .gitignore
└── README.md
```

## Mô tả file

### Entry point

| File      | Purpose  | Usage                   |
| --------- | -------- | ----------------------- |
| `main.py` | CLI mode | `python main.py --scan` |

### Core modules

| File            | Purpose        | Key classes/functions                         |
| --------------- | -------------- | --------------------------------------------- |
| `service.py`    | Business logic | `MalwareScanner`                              |
| `engine.py`     | Scanning       | `calculate_file_hashes()`, `scan_with_yara()` |
| `archive/`      | Archives       | `ArchiveScanner`, backend scanners            |
| `db.py`         | Database       | `connect_db()`, `check_hash_in_db()`          |
| `reporting.py`  | Output         | `print_summary()`, `export_*.txt`             |
| `exceptions.py` | Errors         | `Custom exception classes`                    |

### YARA rules

| Directory                 | Purpose          | Rule types                   |
| ------------------------- | ---------------- | ---------------------------- |
| `rules/core/`             | Generic patterns | PE analysis, packers, crypto |
| `rules/malware_families/` | Specific malware | Emotet, WannaCry, etc.       |

## Import hierarchy

```
main.py
    └── scripts.workflows
        ├── malware_scanner.service
        ├── malware_scanner.engine
        ├── malware_scanner.archive
        ├── malware_scanner.db
        └── malware_scanner.reporting
```

## Ghi chú

- `README.md` chỉ tóm tắt nhanh; tài liệu này là nguồn chuẩn về cấu trúc thư mục.
