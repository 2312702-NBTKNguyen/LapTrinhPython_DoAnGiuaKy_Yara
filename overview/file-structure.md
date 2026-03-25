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
│   ├── cli.py                  # CLI interface
│   ├── service.py              # Business logic (MalwareScanner class)
│   ├── engine.py               # Hash calculation, YARA scanning
│   ├── archive.py              # Archive scanning (ZIP, 7z, RAR)
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
│   ├── generate_samples.py     # Generate fake malware samples
│   ├── test_archive.py         # Archive scanning tests
│   └── samples/                # Fake malware for testing
│       ├── archives/
│       │   ├── test_malware.zip
│       │   └── test_nested.zip
│       ├── test_emotet.exe
│       ├── test_wannacry.exe
│       └── test_lockbit.exe
│
├── database/                   # Database setup
│   ├── 01_create_database.sql
│   └── 02_create_tables.sql
│
├── scripts/                    # Data + workflow scripts
│   ├── get_malware_data.py
│   ├── import_data.py
│   ├── malware_data_filter.py
│   └── workflows.py
│
├── samples/                    # Original test samples
│   ├── test_emotet.txt
│   ├── test_wannacry.txt
│   └── test_lockbit.txt
│
├── logs/                       # Scan reports (generated at runtime)
│   └── scan_report_*.txt/json/csv
│
├── main.py                     # Entry point
├── pyproject.toml              # Project metadata & uv dependencies
├── uv.lock                     # Reproducible builds (uv)
├── requirements.txt            # Python dependencies (pip)
├── .env                        # Environment variables (not in git)
├── .gitignore
└── README.md
```

## Mô tả file

### Entry point

| File      | Purpose  | Usage                          |
| --------- | -------- | ------------------------------ |
| `main.py` | CLI mode | `python main.py --interactive` |

### Core modules

| File            | Purpose        | Key classes/functions                         |
| --------------- | -------------- | --------------------------------------------- |
| `service.py`    | Business logic | `MalwareScanner`                              |
| `engine.py`     | Scanning       | `calculate_file_hashes()`, `scan_with_yara()` |
| `archive.py`    | Archives       | `ArchiveScanner`                              |
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
