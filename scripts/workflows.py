import os
from datetime import datetime
from pathlib import Path

import psycopg2
from dotenv import load_dotenv

from malware_scanner.cli import run_cli
from malware_scanner.service import MalwareScanner
from scripts.get_malware_data import fetch_malware_signatures
from scripts.import_data import import_csv_to_db
from scripts.malware_data_filter import filter_malware_data


ROOT_DIR = Path(__file__).resolve().parent.parent
SQL_CREATE_DB_FILE = ROOT_DIR / "database" / "01_create_database.sql"
SQL_CREATE_TABLES_FILE = ROOT_DIR / "database" / "02_create_tables.sql"
JSON_OUTPUT_FILE = ROOT_DIR / "data" / "malware_signatures.json"
CSV_OUTPUT_FILE = ROOT_DIR / "data" / "malware_signatures.csv"
DEFAULT_DB_NAME = "yara_malware_signatures"
RULES_INDEX_FILE = ROOT_DIR / "rules" / "index.yar"
DISPLAY_WIDTH = 100


def _center_title(text: str) -> str:
    return text.center(DISPLAY_WIDTH)


def _log_info(message: str) -> None:
    print(f"[INFO] {message}")


def _log_success(message: str) -> None:
    print(f"[SUCCESS] {message}")


def _log_warn(message: str) -> None:
    print(f"[WARN] {message}")


def _log_error(message: str) -> None:
    print(f"[ERROR] {message}")


def _print_section(title: str) -> None:
    bar = "=" * DISPLAY_WIDTH
    print(f"\n{bar}")
    print(_center_title(title))
    print(bar)


def _ensure_sql_files_exist() -> None:
    for sql_file in (SQL_CREATE_DB_FILE, SQL_CREATE_TABLES_FILE):
        if not sql_file.exists():
            raise FileNotFoundError(f"Không tìm thấy file SQL: {sql_file}")


def _create_database_if_missing() -> None:
    db_host = os.getenv("DB_HOST", "localhost")
    db_port = os.getenv("DB_PORT", "5432")
    db_user = os.getenv("DB_USER")
    db_password = os.getenv("DB_PASSWORD")
    db_name = os.getenv("DB_NAME", DEFAULT_DB_NAME)
    admin_db = os.getenv("DB_ADMIN_DB", "postgres")

    if not db_user:
        raise ValueError("Thiếu DB_USER trong .env hoặc biến môi trường")

    with open(SQL_CREATE_DB_FILE, "r", encoding="utf-8") as f:
        create_db_sql = f.read().strip()

    _log_info(f"Đọc script: {SQL_CREATE_DB_FILE}")
    if create_db_sql:
        _log_info("Thực thi logic tạo database dựa trên nội dung script SQL...")

    conn = psycopg2.connect(
        host=db_host,
        port=db_port,
        database=admin_db,
        user=db_user,
        password=db_password,
    )
    conn.autocommit = True

    try:
        with conn.cursor() as cur:
            executable_sql = create_db_sql.replace("\\gexec", "").strip()
            if not executable_sql:
                raise RuntimeError("Nội dung SQL tạo database rỗng, không thể thực thi")

            cur.execute(executable_sql)
            create_stmt_row = cur.fetchone()

            if create_stmt_row and create_stmt_row[0]:
                cur.execute(create_stmt_row[0])
                _log_success(f"Đã tạo database '{db_name}' thành công.")
            else:
                _log_warn(f"Database '{db_name}' đã tồn tại. Bỏ qua tạo mới.")
    finally:
        conn.close()


def _create_tables_if_missing() -> None:
    db_host = os.getenv("DB_HOST", "localhost")
    db_port = os.getenv("DB_PORT", "5432")
    db_name = os.getenv("DB_NAME", DEFAULT_DB_NAME)
    db_user = os.getenv("DB_USER")
    db_password = os.getenv("DB_PASSWORD")

    if not db_user:
        raise ValueError("Thiếu DB_USER trong .env hoặc biến môi trường")

    with open(SQL_CREATE_TABLES_FILE, "r", encoding="utf-8") as f:
        create_tables_sql = f.read().strip()

    _log_info(f"Đọc script: {SQL_CREATE_TABLES_FILE}")

    conn = psycopg2.connect(
        host=db_host,
        port=db_port,
        database=db_name,
        user=db_user,
        password=db_password,
    )

    try:
        with conn.cursor() as cur:
            cur.execute(create_tables_sql)
        conn.commit()
        _log_success("Đã cập nhật schema/table thành công.")
    finally:
        conn.close()


def setup_database_from_sql() -> None:
    _ensure_sql_files_exist()
    _create_database_if_missing()
    _create_tables_if_missing()


def _fetch_signatures_data() -> None:
    _log_info("Bắt đầu tải dữ liệu signatures từ API...")

    if JSON_OUTPUT_FILE.exists():
        _log_info(f"Xóa file cũ: {JSON_OUTPUT_FILE}")
        JSON_OUTPUT_FILE.unlink()
    if CSV_OUTPUT_FILE.exists():
        _log_info(f"Xóa file cũ: {CSV_OUTPUT_FILE}")
        CSV_OUTPUT_FILE.unlink()

    fetch_malware_signatures()
    if not JSON_OUTPUT_FILE.exists():
        raise RuntimeError(
            f"Không tìm thấy file JSON output sau khi fetch: {JSON_OUTPUT_FILE}"
        )

    _log_success(f"Đã tải dữ liệu signatures: {JSON_OUTPUT_FILE}")


def _filter_and_import_data() -> None:
    _log_info("Bắt đầu lọc dữ liệu JSON sang CSV...")
    filter_malware_data(str(JSON_OUTPUT_FILE), str(CSV_OUTPUT_FILE))
    if not CSV_OUTPUT_FILE.exists():
        raise RuntimeError(
            f"Không tìm thấy file CSV output sau khi filter: {CSV_OUTPUT_FILE}"
        )

    _log_success(f"Đã tạo file CSV: {CSV_OUTPUT_FILE}")
    _log_info("Bắt đầu import dữ liệu CSV vào PostgreSQL...")
    import_csv_to_db(str(CSV_OUTPUT_FILE))
    _log_success("Hoàn tất import dữ liệu vào PostgreSQL.")


def run_first_startup() -> int:
    _print_section("MALWARE SCANNER - CHẾ ĐỘ KHỞI CHẠY LẦN ĐẦU")

    try:
        load_dotenv()
        os.environ.setdefault("DB_NAME", DEFAULT_DB_NAME)

        _print_section("THIẾT LẬP DATABASE")
        setup_database_from_sql()

        _print_section("TẢI DỮ LIỆU MALWARE")
        _fetch_signatures_data()

        _print_section("LỌC VÀ IMPORT DỮ LIỆU")
        _filter_and_import_data()

        _print_section("HOÀN TẤT KHỞI CHẠY")
        _log_success("Hệ thống đã khởi tạo thành công cho lần chạy đầu tiên.")
        return 0

    except Exception as exc:
        _print_section("KHỞI CHẠY THẤT BẠI")
        _log_error(f"Khởi chạy thất bại: {exc}")
        return 1


def run_update_pipeline() -> int:
    _print_section("MALWARE SCANNER - CHẾ ĐỘ CẬP NHẬT")

    try:
        load_dotenv()
        os.environ.setdefault("DB_NAME", DEFAULT_DB_NAME)

        _print_section("TẢI DỮ LIỆU MALWARE")
        _fetch_signatures_data()

        _print_section("LỌC VÀ IMPORT DỮ LIỆU")
        _filter_and_import_data()

        _print_section("HOÀN TẤT UPDATE")
        _log_success("Đã cập nhật dữ liệu signatures.")
        return 0

    except Exception as exc:
        _print_section("UPDATE THẤT BẠI")
        _log_error(f"Cập nhật thất bại: {exc}")
        return 1


def run_scan_once(target_path: str) -> int:
    resolved_target = Path(target_path).expanduser().resolve()

    if not resolved_target.exists():
        _log_error(f"Đường dẫn không tồn tại: {resolved_target}")
        return 1

    scanner = MalwareScanner(rules_path=str(RULES_INDEX_FILE))

    try:
        _print_section("MALWARE SCANNER - CHẾ ĐỘ QUÉT TỰ ĐỘNG")
        _log_info(f"Target: {resolved_target}")

        if resolved_target.is_file():
            start = datetime.now()
            scanner.scan_target(str(resolved_target))
            duration = (datetime.now() - start).total_seconds()
            scanner.print_summary(duration)
            scanner.finalize_scan_reports(start)
        else:
            scanner.scan_directory(str(resolved_target))

        _log_success("Hoàn tất quét ngầm.")
        return 0
    finally:
        scanner.close()


def run_interactive_mode() -> int:
    _print_section("MALWARE SCANNER - CHẾ ĐỘ TƯƠNG TÁC")
    _log_info("Khởi động CLI tương tác...")
    run_cli()
    _log_success("Đã thoát CLI tương tác.")
    return 0
