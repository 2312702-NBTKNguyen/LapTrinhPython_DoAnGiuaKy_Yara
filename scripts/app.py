from datetime import datetime
from pathlib import Path
import psycopg2
from common.utils import initialize_environment, log_error, log_info, log_success, print_section

from malware_scanner.reporting import finalize_scan_reports, print_summary
from malware_scanner.service import MalwareScanner

from scripts.db_setup import setup_database
from scripts.pipeline import import_signatures

ROOT_DIR = Path(__file__).resolve().parent.parent
JSON_OUTPUT = ROOT_DIR / "data" / "malware_signatures.json"
RULES_INDEX = ROOT_DIR / "rules" / "index.yar"

def init_system() -> int:
    print_section("CHẾ ĐỘ KHỞI CHẠY LẦN ĐẦU")

    try:
        initialize_environment()

        print_section("THIẾT LẬP CƠ SỞ DỮ LIỆU")
        setup_database()

        print_section("LÀM MỚI DỮ LIỆU SIGNATURES")
        import_signatures(JSON_OUTPUT)

        print_section("HOÀN TẤT KHỞI CHẠY")
        log_success("Hệ thống đã khởi tạo và làm mới dữ liệu signatures thành công.")
        return 0

    except (RuntimeError, ValueError, OSError, psycopg2.Error) as exc:
        print('-' * 100)
        log_error(f"Khởi chạy thất bại: {exc}")
        return 1

def scan_target(target_path: str | None = None) -> int:
    if not target_path:
        print_section("CHẾ ĐỘ QUÉT")
        target_path = input("Nhập đường dẫn file hoặc thư mục cần quét: ").strip().strip('"\'')

    if not target_path:
        log_error("Bạn chưa nhập đường dẫn để quét.")
        return 1

    resolved_target = Path(target_path).expanduser().resolve()

    if not resolved_target.exists():
        log_error(f"Đường dẫn không tồn tại: {resolved_target}")
        return 1

    scanner = MalwareScanner(rules_path=str(RULES_INDEX))

    try:
        print_section("MALWARE SCANNER - CHẾ ĐỘ QUÉT")
        log_info(f"Target: {resolved_target}")

        if resolved_target.is_file():
            start = datetime.now()
            scanner.scan_target(str(resolved_target))
            duration = (datetime.now() - start).total_seconds()
            print_summary(scanner.stats, duration)
            finalize_scan_reports(scanner.db_conn, start)
        else:
            scanner.scan_directory(str(resolved_target))

        log_success("Hoàn tất quét.")
        return 0
    finally:
        scanner.close()
