import psycopg2
from pathlib import Path
from collections.abc import Callable
from config import Config


def _db_conn() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=Config.DB_HOST,
        port=Config.DB_PORT,
        dbname=Config.DB_NAME,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
    )


def _log(log_callback: Callable[[str], None] | None, message: str) -> None:
    if log_callback:
        log_callback(message)


def init_db(log_callback: Callable[[str], None] | None = None) -> None:
    root = Path(__file__).resolve().parent.parent
    db_sql_path = root / "database" / "01_create_database.sql"
    table_sql_path = root / "database" / "02_create_tables.sql"

    for file in (db_sql_path, table_sql_path):
        if not file.exists():
            message = f"Không tìm thấy file SQL: {file}"
            _log(log_callback, message)
            raise FileNotFoundError(message)

    with open(db_sql_path, "r", encoding="utf-8") as file_obj:
        db_sql = file_obj.read().strip()
    with open(table_sql_path, "r", encoding="utf-8") as file_obj:
        table_sql = file_obj.read().strip()

    _log(log_callback, f"Đọc script: {db_sql_path}")
    if db_sql:
        _log(log_callback, "Thực thi logic tạo database dựa trên nội dung script SQL...")

    conn = _db_conn()
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
                _log(log_callback, f"Đã tạo database '{Config.DB_NAME}' thành công.")
            else:
                _log(log_callback, f"Database '{Config.DB_NAME}' đã tồn tại. Bỏ qua tạo mới.")
    finally:
        conn.close()

    _log(log_callback, f"Đọc script: {table_sql_path}")
    conn = _db_conn()
    try:
        with conn.cursor() as cursor:
            cursor.execute(table_sql)
        conn.commit()
        _log(log_callback, "Đã cập nhật schema/table thành công.")
    finally:
        conn.close()
