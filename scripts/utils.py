from __future__ import annotations

import os


DEFAULT_DB_NAME = "yara_malware_signatures"


def log_info(message: str) -> None:
    print(f"[INFO] {message}")


def log_success(message: str) -> None:
    print(f"[SUCCESS] {message}")


def log_warn(message: str) -> None:
    print(f"[WARN] {message}")


def log_error(message: str) -> None:
    print(f"[ERROR] {message}")


def get_db_connection_kwargs(db_name: str | None = None, *, admin: bool = False) -> dict[str, str | None]:
    selected_db = db_name or os.getenv("DB_NAME") or DEFAULT_DB_NAME
    if admin:
        selected_db = os.getenv("DB_ADMIN_DB", "postgres")

    return {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": os.getenv("DB_PORT", "5432"),
        "database": selected_db,
        "user": os.getenv("DB_USER"),
        "password": os.getenv("DB_PASSWORD"),
    }
