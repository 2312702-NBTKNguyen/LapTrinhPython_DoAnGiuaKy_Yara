import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

from malware_scanner.reporting import finalize_scan_reports, print_summary
from malware_scanner.service import MalwareScanner
from malware_scanner.ui import print_section
from scripts.db_setup import setup_database_from_sql
from scripts.pipeline import run_data_pipeline
from scripts.utils import (
    DEFAULT_DB_NAME,
    log_error,
    log_info,
    log_success,
)


ROOT_DIR = Path(__file__).resolve().parent.parent
JSON_OUTPUT_FILE = ROOT_DIR / "data" / "malware_signatures.json"
CSV_OUTPUT_FILE = ROOT_DIR / "data" / "malware_signatures.csv"
RULES_INDEX_FILE = ROOT_DIR / "rules" / "index.yar"


def run_first_startup() -> int:
    print_section("MALWARE SCANNER - CHẾ ĐỘ KHỞI CHẠY LẦN ĐẦU")

    try:
        load_dotenv()
        os.environ.setdefault("DB_NAME", DEFAULT_DB_NAME)

        print_section("THIẾT LẬP DATABASE")
        setup_database_from_sql()

        print_section("TẢI/LỌC/IMPORT DỮ LIỆU")
        run_data_pipeline(JSON_OUTPUT_FILE, CSV_OUTPUT_FILE)

        print_section("HOÀN TẤT KHỞI CHẠY")
        log_success("Hệ thống đã khởi tạo thành công cho lần chạy đầu tiên.")
        return 0

    except Exception as exc:
        print_section("KHỞI CHẠY THẤT BẠI")
        log_error(f"Khởi chạy thất bại: {exc}")
        return 1


def run_update_pipeline() -> int:
    print_section("MALWARE SCANNER - CHẾ ĐỘ CẬP NHẬT")

    try:
        load_dotenv()
        os.environ.setdefault("DB_NAME", DEFAULT_DB_NAME)

        print_section("TẢI/LỌC/IMPORT DỮ LIỆU")
        run_data_pipeline(JSON_OUTPUT_FILE, CSV_OUTPUT_FILE)

        print_section("HOÀN TẤT UPDATE")
        log_success("Đã cập nhật dữ liệu signatures.")
        return 0

    except Exception as exc:
        print_section("UPDATE THẤT BẠI")
        log_error(f"Cập nhật thất bại: {exc}")
        return 1


def run_scan_once(target_path: str | None = None) -> int:
    if not target_path:
        print_section("MALWARE SCANNER - CHẾ ĐỘ QUÉT")
        target_path = input("Nhập đường dẫn file hoặc thư mục cần quét: ").strip().strip('"\'')

    if not target_path:
        log_error("Bạn chưa nhập đường dẫn để quét.")
        return 1

    resolved_target = Path(target_path).expanduser().resolve()

    if not resolved_target.exists():
        log_error(f"Đường dẫn không tồn tại: {resolved_target}")
        return 1

    scanner = MalwareScanner(rules_path=str(RULES_INDEX_FILE))

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
