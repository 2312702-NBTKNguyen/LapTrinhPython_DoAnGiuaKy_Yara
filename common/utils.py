import os


def log_info(message: str) -> None:
    print(f"[INFO] {message}")


def log_success(message: str) -> None:
    print(f"[SUCCESS] {message}")


def log_warn(message: str) -> None:
    print(f"[WARN] {message}")


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


def center_text(text: str, width: int = 100, fill_char: str = " ") -> str:
    return text.center(width, fill_char)


def print_section(title: str, width: int = 100) -> None:
    bar = "=" * width
    print(f"\n{bar}")
    print(center_text(title, width=width))
    print(bar)
