import json, os
import pandas as pd
import psycopg2, requests

from pathlib import Path
from common.utils import log_info, log_success, log_error, log_warn, get_db_connection
from dotenv import load_dotenv
from psycopg2.extras import execute_values

load_dotenv()

def fetch_malware_signatures(output_file: str = "./data/malware_signatures.json") -> None:
    url = "https://mb-api.abuse.ch/api/v1/"
    auth_key = os.getenv("MB_AUTH_KEY")

    if not auth_key:
        log_error("Chưa có API key trong file .env hoặc biến môi trường hệ thống.")
        return

    headers = {
        "Auth-Key": auth_key,
        "User-Agent": "Python-MalwareBazaar-Client/1.0",
    }

    # Danh sách các signatures phổ biến
    signatures = [
        # Nhóm Info Stealers (Mã độc đánh cắp thông tin)
        "RedLineStealer", "LokiBot", "AgentTesla", "Formbook",
        # Nhóm Banking Trojans & Botnets
        "Emotet", "TrickBot", "Mirai", "Dridex", 
        # Nhóm Ransomware (Mã độc tống tiền)
        "WannaCry", "LockBit", "Conti", "Ryuk",
        # Nhóm RATs (Remote Access Trojans - Trojan điều khiển từ xa)
        "RemcosRAT", "njRAT"
    ]    

    log_info(f"Gửi request đến MalwareBazaar API với {len(signatures)} signatures...")
    log_info(f"Danh sách các signatures: {', '.join(signatures)}")
    try:
        all_malware = []
        successful_requests = 0
        failed_requests = 0

        for sig in signatures:
            json_data = fetch_signature(sig, url, headers)
            if json_data is None:
                failed_requests += 1
                continue

            query_status = json_data.get("query_status")
            if query_status == "ok":
                signature_records = json_data.get("data", [])
                log_success(
                    f"Signature {sig}: nhận {len(signature_records)} records."
                )
                all_malware.extend(signature_records)
                successful_requests += 1
                continue

            if query_status in ("no_results", "sig_not_found", "signature_not_found"):
                log_warn(f"Signature {sig}: không có dữ liệu ({query_status}).")
                successful_requests += 1
                continue

            log_error(f"Signature {sig}: lỗi từ API ({query_status}).")
            failed_requests += 1

        if successful_requests == 0:
            log_error("Không có request nào thành công.")
            return

        unique_malware = []
        seen_hashes = set()
        for record in all_malware:
            sha256_hash = record.get("sha256_hash")
            if sha256_hash in seen_hashes:
                continue

            if sha256_hash:
                seen_hashes.add(sha256_hash)
            unique_malware.append(record)

        with open(output_file, "w", encoding="utf-8") as file_obj:
            json.dump(unique_malware, file_obj, indent=4)

        log_success(f"Đã lưu {len(unique_malware)} bản ghi vào '{output_file}'.")
        log_info(f"Đã lọc {len(all_malware) - len(unique_malware)} bản ghi trùng lặp.")
        log_info(
            f"Tổng kết: {successful_requests} request thành công, " f"{failed_requests} request lỗi."
        )

    except requests.exceptions.RequestException as exc:
        log_error(f"Lỗi kết nối: {exc}")


def fetch_signature(sig: str, url: str, headers: dict[str, str]) -> dict | None:
    payload = {
        "query": "get_siginfo",
        "signature": sig,
        "limit": 500,
    }

    log_info(f"Lấy dữ liệu signature: {sig}")
    try:
        response = requests.post(url, data=payload, headers=headers, timeout=60)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as exc:
        status_code = exc.response.status_code if exc.response else "unknown"
        log_error(f"Signature {sig}: lỗi HTTP {status_code} ({exc}), bỏ qua.")
    except requests.exceptions.RequestException as exc:
        log_error(f"Signature {sig}: lỗi kết nối ({exc}), bỏ qua.")
    except ValueError:
        log_warn(
            f"Signature {sig}: API trả về dữ liệu không phải JSON, bỏ qua."
        )

    return None

def filter_malware_data(input_file: str) -> pd.DataFrame | None:
    log_info(f"Đọc dữ liệu từ file: {input_file}")

    try:
        dataframe = pd.read_json(input_file)

        if dataframe.empty:
            log_warn("File input rỗng, không có dữ liệu để xử lý.")
            return None

        columns = [
            "file_name", "signature", "file_type", "first_seen", "file_type_mime",
            "md5_hash", "sha1_hash", "sha256_hash", "sha3_384_hash"
        ]

        selected_data = {}
        for col in columns:
            if col in dataframe.columns:
                selected_data[col] = dataframe[col]
            else:
                selected_data[col] = "Unknown"

        cleaned = pd.DataFrame(selected_data, columns=columns)
        cleaned.fillna("Unknown", inplace=True)
        log_success("Đã chuẩn hóa dữ liệu JSON.")
        return cleaned

    except ValueError as exc:
        log_error(f"Lỗi khi đọc file JSON: {exc}")
    except FileNotFoundError:
        log_error(f"Không tìm thấy file {input_file}.")
    except Exception as exc:
        log_error(f"Đã xảy ra lỗi: {exc}")

    return None


def import_dataframe_to_db(dataframe: pd.DataFrame) -> None:
    log_info("Bắt đầu nhập dữ liệu vào PostgreSQL...")

    try:
        db_config = get_db_connection()
        host = db_config.get("host")
        port = db_config.get("port")
        dbname = db_config.get("database")
        user = db_config.get("user")
        password = db_config.get("password")

        if not all([host, port, dbname, user, password]):
            log_error("Thiếu cấu hình kết nối database trong biến môi trường.")
            return

        conn = psycopg2.connect(
            host=host,
            port=port,
            dbname=dbname,
            user=user,
            password=password,
        )
        cursor = conn.cursor()
        log_success("Kết nối Database thành công.")
    except Exception as exc:
        log_error(f"Lỗi kết nối Database: {exc}")
        return

    records_to_insert = []
    for row in dataframe.to_dict(orient="records"):
        first_seen = row["first_seen"] if row["first_seen"] != "Unknown" else None
        records_to_insert.append(
            (
                row["file_name"], row["signature"], row["file_type"], first_seen, row["file_type_mime"], 
                row["md5_hash"], row["sha1_hash"], row["sha256_hash"], row["sha3_384_hash"],
            )
        )

    if not records_to_insert:
        log_warn("Không có bản ghi nào để thêm vào database.")
        cursor.close()
        conn.close()
        log_info("Đóng kết nối Database.")
        return

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
        log_success(f"Đã thêm {len(records_to_insert)} bản ghi vào database.")
    except Exception as exc:
        conn.rollback()
        log_error(f"Lỗi khi thực hiện insert: {exc}")
    finally:
        cursor.close()
        conn.close()
        log_info("Đóng kết nối Database.")

def refresh_signatures(json_output_file: Path) -> None:
    if json_output_file.exists():
        log_info(f"Xóa file cũ: {json_output_file}")
        json_output_file.unlink()

    fetch_malware_signatures(output_file=str(json_output_file))
    if not json_output_file.exists():
        raise RuntimeError(
            f"Không tìm thấy file JSON sau khi fetch: {json_output_file}"
        )

    log_success(f"Dữ liệu signatures được lưu tại: {json_output_file}")
    print("-" * 100)


def filter_and_import_signatures(json_output_file: Path) -> None:
    log_info("Bắt đầu lọc dữ liệu JSON.")
    cleaned_dataframe = filter_malware_data(str(json_output_file))
    if cleaned_dataframe is None or cleaned_dataframe.empty:
        raise RuntimeError(
            f"Không tạo được DataFrame hợp lệ từ file JSON: {json_output_file}"
        )

    log_success(f"Đã tạo DataFrame với {len(cleaned_dataframe)} bản ghi.")
    import_dataframe_to_db(cleaned_dataframe)
    log_success("Hoàn tất nhập dữ liệu vào PostgreSQL.")


def import_signatures(json_output_file: Path) -> None:
    refresh_signatures(json_output_file)
    filter_and_import_signatures(json_output_file)
