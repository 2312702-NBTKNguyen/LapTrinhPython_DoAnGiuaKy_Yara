import psycopg2
from pathlib import Path
from common.utils import log_error, log_info, log_success, log_warn
from config import Config


def _create_setup_connection() -> psycopg2.extensions.connection:
    """Tạo connection đơn lẻ cho setup (không dùng pool)."""
    return psycopg2.connect(
        host=Config.DB_HOST,
        port=Config.DB_PORT,
        dbname=Config.DB_NAME,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
    )


def setup_database() -> None:
    root_dir = Path(__file__).resolve().parent.parent
    sql_create_db = root_dir / "database" / "01_create_database.sql"
    sql_create_table = root_dir / "database" / "02_create_tables.sql"

    for file in (sql_create_db, sql_create_table):
        if not file.exists():
            message = f"Không tìm thấy file SQL: {file}"
            log_error(message)
            raise FileNotFoundError(message)

    with open(sql_create_db, "r", encoding="utf-8") as file_obj:
        create_db_sql = file_obj.read().strip()
    with open(sql_create_table, "r", encoding="utf-8") as file_obj:
        create_tables_sql = file_obj.read().strip()

    log_info(f"Đọc script: {sql_create_db}")
    if create_db_sql:
        log_info("Thực thi logic tạo database dựa trên nội dung script SQL...")

    conn = _create_setup_connection()
    conn.autocommit = True
    try:
        with conn.cursor() as cursor:
            executable_sql = create_db_sql.replace("\\gexec", "").strip()
            if not executable_sql:
                raise RuntimeError("Nội dung SQL tạo database rỗng, không thể thực thi")

            cursor.execute(executable_sql)
            create_stmt_row = cursor.fetchone()
            if create_stmt_row and create_stmt_row[0]:
                cursor.execute(create_stmt_row[0])
                log_success(f"Đã tạo database '{Config.DB_NAME}' thành công.")
            else:
                log_warn(f"Database '{Config.DB_NAME}' đã tồn tại. Bỏ qua tạo mới.")
    finally:
        conn.close()

    log_info(f"Đọc script: {sql_create_table}")
    conn = _create_setup_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(create_tables_sql)
        conn.commit()
        log_success("Đã cập nhật schema/table thành công.")
    finally:
        conn.close()
