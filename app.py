import psycopg2

from datetime import datetime
from pathlib import Path
from malware_scanner.utils import log_error, log_info, log_success, print_section
from config import Config
from malware_scanner.reporting import write_report, show_summary
from malware_scanner.scanner import ScannerEngine
from data_tools.db_setup import setup_db
from data_tools.data_loader import sync_signatures

ROOT_DIR = Path(__file__).resolve().parent.parent
JSON_OUTPUT = ROOT_DIR / "data" / "malware_signatures.json"

def boot() -> int:
    print_section("CHẾ ĐỘ KHỞI TẠO DỮ LIỆU")

    try:
        print_section("THIẾT LẬP CƠ SỞ DỮ LIỆU")
        setup_db()

        print_section("LÀM MỚI DỮ LIỆU SIGNATURES")
        sync_signatures(JSON_OUTPUT)

        print_section("HOÀN TẤT KHỞI CHẠY")
        log_success("Hệ thống đã khởi tạo và làm mới dữ liệu signatures thành công.")
        return 0

    except (RuntimeError, ValueError, OSError, psycopg2.Error) as exc:
        print("-" * 100)
        log_error(f"Khởi chạy thất bại: {exc}")
        return 1

def _resolve_target(target: str) -> Path | None:
    resolved = Path(target).expanduser().resolve()
    if not resolved.exists():
        log_error(f"Đường dẫn không tồn tại: {resolved}")
        return None
    return resolved

def _scan_and_report(scanner: ScannerEngine, target: Path) -> None:
    start = datetime.now()

    if target.is_file():
        scanner.scan(str(target))
        duration = (datetime.now() - start).total_seconds()
        metrics = scanner.metrics
    else:
        metrics, duration = scanner.scan_dir(str(target))

    show_summary(metrics, duration)
    write_report(scanner.store, start)

def scan(target: str | None = None) -> int:
    if not target:
        print_section("CHẾ ĐỘ QUÉT")
        target = input("Nhập đường dẫn file hoặc thư mục cần quét: ").strip().strip('"\'')

    if not target:
        log_error("Chưa nhập đường dẫn để quét.")
        return 1

    resolved = _resolve_target(target)
    if resolved is None:
        return 1

    scanner = ScannerEngine(rules_path=Config.YARA_RULES_PATH)
    try:
        print_section("CHẾ ĐỘ QUÉT")
        log_info(f"Target: {resolved}")

        _scan_and_report(scanner, resolved)

        log_success("Hoàn tất quét.")
        return 0
    finally:
        scanner.close()