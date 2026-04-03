import os
import psycopg2


def log_info(message: str) -> None:
    print(f"[INFO] {message}")


def log_success(message: str) -> None:
    print(f"[SUCCESS] {message}")


def log_warn(message: str) -> None:
    print(f"[WARNING] {message}")


def log_error(message: str) -> None:
    print(f"[ERROR] {message}")


def get_db_connection() -> dict[str, str | None]:
    return {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": os.getenv("DB_PORT", "5432"),
        "database": os.getenv("DB_NAME"),
        "user": os.getenv("DB_USER"),
        "password": os.getenv("DB_PASSWORD"),
    }


def create_db_connection() -> psycopg2.extensions.connection:
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


def center_text(text: str, width: int = 100, fill_char: str = " ") -> str:
    return text.center(width, fill_char)


def print_section(title: str, width: int = 100) -> None:
    bar = "=" * width
    print(f"\n{bar}")
    print(center_text(title, width=width))
    print(bar)
