import sqlite3

from pathlib import Path
from config import Config
from collections.abc import Callable

def connect_db() -> sqlite3.Connection:
    root = Path(__file__).resolve().parent.parent
    db_path = Path(Config.DB_FILE).expanduser()
    if not db_path.is_absolute():
        db_path = root / db_path

    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path), timeout=Config.DB_TIMEOUT_SECONDS)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute(f"PRAGMA busy_timeout = {Config.DB_BUSY_TIMEOUT_MS};")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(log_callback: Callable[[str], None] | None = None) -> None:
    _ = log_callback
    root = Path(__file__).resolve().parent.parent
    schema_sql_path = root / "database" / "create_schema.sql"

    if not schema_sql_path.exists():
        message = f"Không tìm thấy file SQL: {schema_sql_path}"
        raise FileNotFoundError(message)

    with open(schema_sql_path, "r", encoding="utf-8") as file_obj:
        schema_sql = file_obj.read().strip()

    if not schema_sql:
        message = f"Nội dung schema rỗng: {schema_sql_path}"
        raise RuntimeError(message)

    conn = connect_db()
    try:
        conn.executescript(schema_sql)
        conn.commit()
    finally:
        conn.close()
