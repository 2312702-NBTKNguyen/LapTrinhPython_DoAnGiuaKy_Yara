from __future__ import annotations

import os
from pathlib import Path

import psycopg2

from scripts.utils import (
    DEFAULT_DB_NAME,
    get_db_connection_kwargs,
    log_info,
    log_success,
    log_warn,
)


ROOT_DIR = Path(__file__).resolve().parent.parent
SQL_CREATE_DB_FILE = ROOT_DIR / "database" / "01_create_database.sql"
SQL_CREATE_TABLES_FILE = ROOT_DIR / "database" / "02_create_tables.sql"


def _ensure_sql_files_exist() -> None:
    for sql_file in (SQL_CREATE_DB_FILE, SQL_CREATE_TABLES_FILE):
        if not sql_file.exists():
            raise FileNotFoundError(f"Không tìm thấy file SQL: {sql_file}")


def _create_database_if_missing() -> None:
    db_user = os.getenv("DB_USER")
    db_name = os.getenv("DB_NAME", DEFAULT_DB_NAME)

    if not db_user:
        raise ValueError("Thiếu DB_USER trong .env hoặc biến môi trường")

    with open(SQL_CREATE_DB_FILE, "r", encoding="utf-8") as file_obj:
        create_db_sql = file_obj.read().strip()

    log_info(f"Đọc script: {SQL_CREATE_DB_FILE}")
    if create_db_sql:
        log_info("Thực thi logic tạo database dựa trên nội dung script SQL...")

    conn = psycopg2.connect(**get_db_connection_kwargs(admin=True))
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
                log_success(f"Đã tạo database '{db_name}' thành công.")
            else:
                log_warn(f"Database '{db_name}' đã tồn tại. Bỏ qua tạo mới.")
    finally:
        conn.close()


def _create_tables_if_missing() -> None:
    db_user = os.getenv("DB_USER")

    if not db_user:
        raise ValueError("Thiếu DB_USER trong .env hoặc biến môi trường")

    with open(SQL_CREATE_TABLES_FILE, "r", encoding="utf-8") as file_obj:
        create_tables_sql = file_obj.read().strip()

    log_info(f"Đọc script: {SQL_CREATE_TABLES_FILE}")

    conn = psycopg2.connect(**get_db_connection_kwargs())
    try:
        with conn.cursor() as cursor:
            cursor.execute(create_tables_sql)
        conn.commit()
        log_success("Đã cập nhật schema/table thành công.")
    finally:
        conn.close()


def setup_database_from_sql() -> None:
    _ensure_sql_files_exist()
    _create_database_if_missing()
    _create_tables_if_missing()
