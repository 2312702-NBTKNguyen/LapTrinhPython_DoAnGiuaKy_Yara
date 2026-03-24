import psycopg2
import csv
import os

from dotenv import load_dotenv
from psycopg2.extras import execute_values

load_dotenv()


def _log_info(message: str) -> None:
    print(f"[INFO] {message}")


def _log_success(message: str) -> None:
    print(f"[SUCCESS] {message}")


def _log_warn(message: str) -> None:
    print(f"[WARN] {message}")


def _log_error(message: str) -> None:
    print(f"[ERROR] {message}")


def import_csv_to_db(csv_file_path):
    _log_info(f"Bắt đầu import dữ liệu từ {csv_file_path} vào PostgreSQL...")

    try:
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST", "localhost"),
            port=os.getenv("DB_PORT", "5432"),
            database=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD") 
        )
        cursor = conn.cursor()
        _log_success("Kết nối Database thành công.")
    except Exception as e:
        _log_error(f"Lỗi kết nối Database: {e}")
        return
    
    records_to_insert = []
    try:
        with open(csv_file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                first_seen = row['first_seen'] if row['first_seen'] != 'Unknown' else None
                records_to_insert.append((
                    row['file_name'],
                    row['signature'],
                    row['file_type'],
                    first_seen,
                    row['file_type_mime'],
                    row['md5_hash'],
                    row['sha1_hash'],
                    row['sha256_hash'],
                    row['sha3_384_hash']
                ))
    except FileNotFoundError:
        _log_error(f"Không tìm thấy file {csv_file_path}.")
        return
    
    if records_to_insert:
        insert_query = """
            INSERT INTO malware_signatures (
                file_name, signature, file_type, first_seen, file_type_mime,
                md5_hash, sha1_hash, sha256_hash, sha3_384_hash
            ) VALUES %s
            ON CONFLICT (sha256_hash) DO NOTHING;
        """
        try:
            execute_values(cursor, insert_query, records_to_insert)
            conn.commit()
            _log_success(f"Đã thêm {len(records_to_insert)} records vào database.")
        except Exception as e:
            conn.rollback()
            _log_error(f"Lỗi khi thực hiện insert: {e}")
        finally:
            cursor.close()
            conn.close()
            _log_info("Đóng kết nối Database.")
    else:
        _log_warn("Không có records nào để thêm vào database.")

if __name__ == "__main__":
    import_csv_to_db('./data/malware_signatures.csv')