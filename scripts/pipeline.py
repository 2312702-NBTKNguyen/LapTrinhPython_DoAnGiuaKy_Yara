import json, os, requests
import pandas as pd
import psycopg2

from pathlib import Path
from common.utils import create_db_connection, initialize_environment, log_error, log_info, log_success, log_warn
from psycopg2.extras import execute_values


def fetch_malware_signatures(output_file: str = "./data/malware_signatures.json") -> None:
    url = "https://mb-api.abuse.ch/api/v1/"
    auth_key = os.getenv("MB_AUTH_KEY")

    if not auth_key:
        message = "Chưa có API key trong file .env hoặc biến môi trường hệ thống."
        log_error(message)
        raise RuntimeError(message)

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
            log_success(f"Signature {sig}: nhận {len(signature_records)} records.")
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
        message = "Không có request nào thành công."
        log_error(message)
        raise RuntimeError(message)

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
    log_info(f"Tổng kết: {successful_requests} request thành công, " f"{failed_requests} request lỗi.")

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
    except requests.exceptions.RequestException as exc:
        log_error(f"Signature {sig}: lỗi kết nối ({exc}), bỏ qua.")
    except ValueError:
        log_warn(
            f"Signature {sig}: API trả về dữ liệu không phải JSON, bỏ qua."
        )

    return None

def _format_db_error(action: str, exc: Exception) -> str:
    return f"Lỗi Database khi {action}: {exc}"


def _raise_db_runtime_error(action: str, exc: Exception) -> None:
    message = _format_db_error(action, exc)
    log_error(message)
    raise RuntimeError(message) from exc

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

    except FileNotFoundError:
        log_error(f"Không tìm thấy file {input_file}.")
    except ValueError as exc:
        log_error(f"Lỗi khi đọc file JSON: {exc}")

    return None

def import_data_to_db(dataframe: pd.DataFrame) -> None:
    log_info("Bắt đầu nhập dữ liệu vào PostgreSQL...")

    try:
        conn = create_db_connection()
        cursor = conn.cursor()
        log_success("Kết nối Database thành công.")
    except (ValueError, psycopg2.Error) as exc:
        _raise_db_runtime_error("kết nối", exc)

    records_to_insert = []
    for row in dataframe.to_dict(orient="records"):
        first_seen = row["first_seen"] if row["first_seen"] != "Unknown" else None
        records_to_insert.append(
            (row["file_name"], row["signature"], row["file_type"], first_seen, row["file_type_mime"], row["md5_hash"], row["sha1_hash"], row["sha256_hash"], row["sha3_384_hash"])
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
    except psycopg2.Error as exc:
        conn.rollback()
        _raise_db_runtime_error("thực hiện insert", exc)
    finally:
        cursor.close()
        conn.close()
        log_info("Đóng kết nối Database.")

def import_signatures(json_output_file: Path) -> None:
    initialize_environment()
    if json_output_file.exists():
        log_info(f"Xóa file cũ: {json_output_file}")
        json_output_file.unlink()

    fetch_malware_signatures(output_file=str(json_output_file))
    if not json_output_file.exists():
        raise RuntimeError(
            f"Không tìm thấy file JSON sau khi fetch: {json_output_file}"
        )

    log_success(f"Dữ liệu signatures được lưu tại: {json_output_file}")
    log_info("-" * 100)

    log_info("Bắt đầu lọc dữ liệu JSON.")
    cleaned_dataframe = filter_malware_data(str(json_output_file))
    if cleaned_dataframe is None or cleaned_dataframe.empty:
        raise RuntimeError(
            f"Không tạo được DataFrame hợp lệ từ file JSON: {json_output_file}"
        )

    log_success(f"Đã tạo DataFrame với {len(cleaned_dataframe)} bản ghi.")
    import_data_to_db(cleaned_dataframe)
    log_success("Hoàn tất nhập dữ liệu vào PostgreSQL.")
