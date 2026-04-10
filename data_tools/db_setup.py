import psycopg2
from pathlib import Path
from malware_scanner.utils import log_error, log_info, log_success, log_warn
from config import Config


def _connect() -> psycopg2.extensions.connection:
    """Tạo connection đơn lẻ cho setup (không dùng pool)."""
    return psycopg2.connect(
        host=Config.DB_HOST,
        port=Config.DB_PORT,
        dbname=Config.DB_NAME,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
    )


def setup_db() -> None:
    root = Path(__file__).resolve().parent.parent
    db_sql_path = root / "database" / "01_create_database.sql"
    table_sql_path = root / "database" / "02_create_tables.sql"

    for file in (db_sql_path, table_sql_path):
        if not file.exists():
            message = f"Không tìm thấy file SQL: {file}"
            log_error(message)
            raise FileNotFoundError(message)

    with open(db_sql_path, "r", encoding="utf-8") as file_obj:
        db_sql = file_obj.read().strip()
    with open(table_sql_path, "r", encoding="utf-8") as file_obj:
        table_sql = file_obj.read().strip()

    log_info(f"Đọc script: {db_sql_path}")
    if db_sql:
        log_info("Thực thi logic tạo database dựa trên nội dung script SQL...")

    conn = _connect()
    conn.autocommit = True
    try:
        with conn.cursor() as cursor:
            sql = db_sql.replace("\\gexec", "").strip()
            if not sql:
                raise RuntimeError("Nội dung SQL tạo database rỗng, không thể thực thi")

            cursor.execute(sql)
            row = cursor.fetchone()
            if row and row[0]:
                cursor.execute(row[0])
                log_success(f"Đã tạo database '{Config.DB_NAME}' thành công.")
            else:
                log_warn(f"Database '{Config.DB_NAME}' đã tồn tại. Bỏ qua tạo mới.")
    finally:
        conn.close()

    log_info(f"Đọc script: {table_sql_path}")
    conn = _connect()
    try:
        with conn.cursor() as cursor:
            cursor.execute(table_sql)
        conn.commit()
        log_success("Đã cập nhật schema/table thành công.")
    finally:
        conn.close()
