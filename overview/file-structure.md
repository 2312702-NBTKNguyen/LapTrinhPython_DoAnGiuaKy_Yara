# Cấu trúc thư mục - YARA Malware Scanner

## Tổng quan

```
LapTrinhPython_DoAnGiuaKy_Yara/
├── overview/                    # Documentation (MỚI)
│   ├── architecture.md         # Kiến trúc hệ thống
│   ├── roadmap.md              # Kế hoạch phát triển
│   ├── file-structure.md       # File này
│   ├── features.md             # Đặc tả tính năng
│   └── contributing.md         # Hướng dẫn đóng góp
│
├── malware_scanner/            # Core package
│   ├── __init__.py
│   ├── cli.py                  # CLI interface
│   ├── service.py              # Business logic (MalwareScanner class)
│   ├── engine.py               # Hash calculation, YARA scanning
│   ├── archive.py              # Archive scanning (ZIP, 7z, RAR) [MỚI]
│   ├── db.py                   # PostgreSQL operations
│   ├── reporting.py            # Report generation
│   ├── exceptions.py           # Custom exceptions [MỚI]
│   └── config.py               # Configuration management [MỚI]
│
├── tui/                        # Terminal UI (MỚI)
│   ├── __init__.py
│   ├── app.py                  # Main Textual app
│   ├── screens/                # Screen components
│   │   ├── __init__.py
│   │   ├── main.py             # Main screen (browser + results)
│   │   ├── scan.py             # Scan configuration screen
│   │   ├── results.py          # Detailed results screen
│   │   ├── rules.py            # YARA rules viewer
│   │   └── history.py          # Scan history screen
│   ├── widgets/                # Reusable widgets
│   │   ├── __init__.py
│   │   ├── file_browser.py     # DirectoryTree widget
│   │   ├── results_table.py    # DataTable for results
│   │   ├── progress.py         # Progress bar widget
│   │   └── rule_viewer.py      # YARA rule display
│   └── styles/
│       └── main.tcss            # CSS styling
│
├── rules/                      # YARA rules
│   ├── index.yar               # Master rule file (includes all)
│   ├── core/                   # Generic detection rules [MỚI]
│   │   ├── pe_analyzer.yar     # PE file analysis
│   │   ├── packer_detection.yar # Packer detection
│   │   ├── crypto_detection.yar # Crypto library detection
│   │   ├── suspicious_apis.yar # Suspicious API calls
│   │   └── network_indicators.yar # Network patterns
│   ├── families/               # Malware family rules
│   │   ├── emotet.yar
│   │   ├── wannacry.yar
│   │   ├── lockbit.yar
│   │   └── ... (14 families)
│   └── test/                   # Test rules
│       └── test_rules.yar
│
├── tests/                      # Test files (MỚI)
│   ├── __init__.py
│   ├── test_engine.py
│   ├── test_archive.py
│   ├── test_service.py
│   └── samples/                # Fake malware for testing
│       ├── archives/
│       │   ├── test_malware.zip
│       │   └── test_malware.7z
│       ├── test_emotet.txt
│       └── test_wannacry.txt
│
├── database/                   # Database setup
│   ├── 01_create_database.sql
│   ├── 02_create_tables.sql
│   └── import_data.py
│
├── src/                        # Data fetching
│   ├── get_malware_data.py
│   └── malware_data_filter.py
│
├── samples/                    # Original test samples
│   ├── test_emotet.txt
│   ├── test_wannacry.txt
│   └── test_lockbit.txt
│
├── logs/                       # Scan reports
│   └── scan_report_*.txt
│
├── scanner.py                  # CLI entry point
├── tui.py                      # TUI entry point [MỚI]
├── requirements.txt            # Python dependencies
├── .env                        # Environment variables (not in git)
├── .gitignore
└── README.md
```

## Mô tả file

### Entry points

| File | Purpose | Usage |
|------|---------|-------|
| `scanner.py` | CLI mode | `python scanner.py` |
| `tui.py` | TUI mode | `python tui.py` |

### Core modules

| File | Purpose | Key classes/functions |
|------|---------|----------------------|
| `service.py` | Business logic | `MalwareScanner` |
| `engine.py` | Scanning | `calculate_file_hashes()`, `scan_with_yara()` |
| `archive.py` | Archives | `ArchiveScanner` |
| `db.py` | Database | `connect_db()`, `check_hash_in_db()` |
| `reporting.py` | Output | `print_summary()`, `export_*.txt` |
| `exceptions.py` | Errors | Custom exception classes |
| `config.py` | Config | `Config` class |

### TUI modules

| File | Purpose | Key classes |
|------|---------|-------------|
| `app.py` | Main app | `MalwareScannerApp` |
| `screens/main.py` | Main view | `MainScreen` |
| `widgets/file_browser.py` | File tree | `MalwareFileTree` |
| `widgets/results_table.py` | Results | `ScanResultsTable` |

### YARA rules

| Directory | Purpose | Rule types |
|-----------|---------|------------|
| `rules/core/` | Generic patterns | PE analysis, packers, crypto |
| `rules/families/` | Specific malware | Emotet, WannaCry, etc. |

## Import hierarchy

```
scanner.py / tui.py
    └── malware_scanner.service
        ├── malware_scanner.engine
        ├── malware_scanner.archive
        ├── malware_scanner.db
        └── malware_scanner.reporting

tui/app.py
    ├── tui.screens.*
    └── tui.widgets.*
        └── malware_scanner.*
```
