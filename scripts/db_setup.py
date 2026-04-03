import os, psycopg2

from pathlib import Path
from common.utils import log_info, log_success, log_warn, get_db_connection

def connect_db() -> psycopg2.extensions.connection:
    db_config = get_db_connection()
    host = db_config.get("host")
    port = db_config.get("port")
    dbname = db_config.get("database")
    user = db_config.get("user")
    password = db_config.get("password")

    if not all([host, port, dbname, user, password]):
        raise ValueError("Thiếu cấu hình kết nối database trong .env hoặc biến môi trường")

    return psycopg2.connect(
        host=host,
        port=port,
        dbname=dbname,
        user=user,
        password=password,
    )


def check_sql_files() -> None:
    root_dir = Path(__file__).resolve().parent.parent

    sql_files = [
        root_dir / "database" / "01_create_database.sql",
        root_dir / "database" / "02_create_tables.sql",
    ]

    for file in sql_files:
        if not file.exists():
            raise FileNotFoundError(f"Không tìm thấy file SQL: {file}")


def create_database_if_missing() -> None:
    root_dir = Path(__file__).resolve().parent.parent
    sql_create_db = root_dir / "database" / "01_create_database.sql"

    with open(sql_create_db, "r", encoding="utf-8") as file_obj:
        create_db_sql = file_obj.read().strip()

    log_info(f"Đọc script: {sql_create_db}")
    if create_db_sql:
        log_info("Thực thi logic tạo database dựa trên nội dung script SQL...")

    conn = connect_db()
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
                log_success(f"Đã tạo database '{os.getenv('DB_NAME')}' thành công.")
            else:
                log_warn(f"Database '{os.getenv('DB_NAME')}' đã tồn tại. Bỏ qua tạo mới.")
    finally:
        conn.close()


def create_tables_if_missing() -> None:
    root_dir = Path(__file__).resolve().parent.parent
    sql_create_table = root_dir / "database" / "02_create_tables.sql"

    with open(sql_create_table, "r", encoding="utf-8") as file_obj:
        create_tables_sql = file_obj.read().strip()

    log_info(f"Đọc script: {sql_create_table}")

    conn = connect_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute(create_tables_sql)
        conn.commit()
        log_success("Đã cập nhật schema/table thành công.")
    finally:
        conn.close()


def setup_database() -> None:
    check_sql_files()
    create_database_if_missing()
    create_tables_if_missing()
