import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Database (SQLite)
    DB_FILE: str = os.getenv("DB_FILE", "data/scanner.db")
    DB_TIMEOUT_SECONDS: float = float(os.getenv("DB_TIMEOUT_SECONDS", "30"))
    DB_BUSY_TIMEOUT_MS: int = int(os.getenv("DB_BUSY_TIMEOUT_MS", "5000"))

    # MalwareBazaar API
    MB_AUTH_KEY: str = os.getenv("MB_AUTH_KEY", "")

    # YARA Rules
    YARA_RULES_PATH: str = os.getenv("YARA_RULES_PATH", "rules/index.yar")

    # Scanner / Anti-Evasion 
    # Giới hạn tối đa dung lượng file đọc vào RAM khi quét YARA
    MAX_FILE_READ_BYTES: int = int(os.getenv("MAX_FILE_READ_BYTES", str(50 * 1024 * 1024)))

    # Các hằng số Anti-Evasion engine
    MIN_VARIANT_BYTES: int = int(os.getenv("MIN_VARIANT_BYTES", "32"))
    MAX_VARIANT_BYTES: int = int(os.getenv("MAX_VARIANT_BYTES", str(5 * 1024 * 1024)))
    MAX_BASE64_BLOBS: int = int(os.getenv("MAX_BASE64_BLOBS", "40"))
    MAX_ZIP_ENTRIES: int = int(os.getenv("MAX_ZIP_ENTRIES", "20"))

    # Concurrency
    THREAD_POOL_WORKERS: int = int(os.getenv("THREAD_POOL_WORKERS", str(os.cpu_count() or 4)))
