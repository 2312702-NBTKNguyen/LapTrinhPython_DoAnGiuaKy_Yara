import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Database
    DB_HOST: str = os.getenv("DB_HOST", "localhost")
    DB_PORT: int = int(os.getenv("DB_PORT", "5432"))
    DB_NAME: str = os.getenv("DB_NAME", "yara_malware_signatures")
    DB_USER: str = os.getenv("DB_USER", "postgres")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "")

    # Connection Pool
    DB_POOL_MIN: int = int(os.getenv("DB_POOL_MIN", "1"))
    DB_POOL_MAX: int = int(os.getenv("DB_POOL_MAX", "5"))

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
