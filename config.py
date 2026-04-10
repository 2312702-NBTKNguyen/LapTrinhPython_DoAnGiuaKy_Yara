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
    DB_POOL_MIN: int = int(os.getenv("DB_POOL_MIN", "10"))
    DB_POOL_MAX: int = int(os.getenv("DB_POOL_MAX", "50"))

    # MalwareBazaar API
    MB_AUTH_KEY: str = os.getenv("MB_AUTH_KEY", "")

    # YARA Rules
    YARA_RULES_PATH: str = os.getenv("YARA_RULES_PATH", "rules/index.yar")

    # Hashing 
    HASH_CHUNK_SIZE: int = int(os.getenv("HASH_CHUNK_SIZE", "4096"))

    # Scanner / Anti-Evasion 
    # Giới hạn tối đa dung lượng file đọc vào RAM khi quét YARA
    MAX_FILE_READ_BYTES: int = int(os.getenv("MAX_FILE_READ_BYTES", str(50 * 1024 * 1024)))

    # Các hằng số Anti-Evasion engine
    MIN_VARIANT_BYTES: int = int(os.getenv("MIN_VARIANT_BYTES", "32"))
    MAX_VARIANT_BYTES: int = int(os.getenv("MAX_VARIANT_BYTES", str(5 * 1024 * 1024)))
    SAMPLE_SIZE: int = int(os.getenv("SAMPLE_SIZE", "32768"))
    MIN_PRINTABLE_RATIO: float = float(os.getenv("MIN_PRINTABLE_RATIO", "0.75"))
    MAX_SCRIPT_FRAGMENTS: int = int(os.getenv("MAX_SCRIPT_FRAGMENTS", "4000"))
    MAX_PRINTABLE_STRINGS: int = int(os.getenv("MAX_PRINTABLE_STRINGS", "2000"))
    MAX_BASE64_BLOBS: int = int(os.getenv("MAX_BASE64_BLOBS", "40"))

    # Concurrency
    THREAD_POOL_WORKERS: int = int(os.getenv("THREAD_POOL_WORKERS", str(os.cpu_count() or 4)))
