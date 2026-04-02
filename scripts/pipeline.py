from inspect import signature
from pathlib import Path

import csv
import json
import os

import pandas as pd
import psycopg2
import requests

from dotenv import load_dotenv

from scripts.utils import log_info, log_success, log_error, log_warn, get_db_connection

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
    print("-" * 100)

    try:
        all_malware = []
        successful_requests = 0
        failed_requests = 0

        for signature in signatures:
            payload = {
                "query": "get_siginfo",
                "signature": signature,
                "limit": 500,
            }

            log_info(f"Lấy dữ liệu cho signature: {signature}")
            try:
                response = requests.post(url, data=payload, headers=headers, timeout=60)
            except requests.exceptions.RequestException as exc:
                log_error(f"Signature {signature}: lỗi kết nối ({exc}), bỏ qua.")
                failed_requests += 1
                continue

            try:
                response.raise_for_status()
            except requests.exceptions.RequestException as exc:
                log_error(f"Signature {signature}: lỗi HTTP ({exc}), bỏ qua.")
                failed_requests += 1
                continue

            try:
                json_data = response.json()
            except ValueError:
                log_warn(
                    f"Signature {signature}: API trả về dữ liệu không phải JSON, bỏ qua."
                )
                continue

            query_status = json_data.get("query_status")
            if query_status == "ok":
                signature_records = json_data.get("data", [])
                log_success(
                    f"Signature {signature}: nhận {len(signature_records)} records."
                )
                all_malware.extend(signature_records)
                successful_requests += 1
                continue

            if query_status in ("no_results", "sig_not_found", "signature_not_found"):
                log_warn(f"Signature {signature}: không có dữ liệu ({query_status}).")
                successful_requests += 1
                continue

            log_error(f"Signature {signature}: lỗi từ API ({query_status}).")
            failed_requests += 1

        if successful_requests == 0:
            log_error("Không có request nào thành công, không ghi đè file output.")
            return

        unique_malware = []
        seen_hashes = set()
        for record in all_malware:
            sha256_hash = record.get("sha256_hash")
            if sha256_hash and sha256_hash in seen_hashes:
                continue

            if sha256_hash:
                seen_hashes.add(sha256_hash)
            unique_malware.append(record)

        with open(output_file, "w", encoding="utf-8") as file_obj:
            json.dump(unique_malware, file_obj, indent=4)

        duplicate_count = len(all_malware) - len(unique_malware)
        log_success(f"Đã lưu {len(unique_malware)} records vào '{output_file}'.")
        log_info(f"Đã lọc {duplicate_count} records trùng lặp.")
        log_info(
            f"Tổng kết: {successful_requests} request thành công, "
            f"{failed_requests} request lỗi."
        )

    except requests.exceptions.RequestException as exc:
        log_error(f"Lỗi kết nối: {exc}")


def filter_malware_data(input_file: str, output_file: str) -> None:
    log_info(f"Đọc dữ liệu từ file: {input_file}")

    try:
        dataframe = pd.read_json(input_file)

        if dataframe.empty:
            log_warn("File input rỗng, không có dữ liệu để xử lý.")
            return

        log_info(f"Dữ liệu gốc: {len(dataframe)} dòng.")
        columns_to_keep = [
            "file_name", "signature", "file_type", "first_seen", "file_type_mime",
            "md5_hash", "sha1_hash", "sha256_hash", "sha3_384_hash"
        ]

        selected_data = {}
        for column in columns_to_keep:
            if column in dataframe.columns:
                selected_data[column] = dataframe[column]
            else:
                selected_data[column] = "Unknown"

        cleaned = pd.DataFrame(selected_data, columns=columns_to_keep)
        cleaned.fillna("Unknown", inplace=True)
        cleaned.to_csv(output_file, index=False, encoding="utf-8")

        log_success(f"Lưu dữ liệu đã lọc vào file: {output_file}")
        log_info("Các cột hiện tại trong bộ dữ liệu:")
        print(str(cleaned.columns.tolist()))

    except ValueError as exc:
        log_error(f"Lỗi khi đọc file JSON: {exc}")
    except FileNotFoundError:
        log_error(f"Không tìm thấy file {input_file}.")
    except Exception as exc:
        log_error(f"Đã xảy ra lỗi: {exc}")


def import_csv_to_db(csv_file_path: str) -> None:
    log_info(f"Bắt đầu import dữ liệu từ {csv_file_path} vào PostgreSQL...")

    try:
        conn = psycopg2.connect(**get_db_connection())
        cursor = conn.cursor()
        log_success("Kết nối Database thành công.")
    except Exception as exc:
        log_error(f"Lỗi kết nối Database: {exc}")
        return

    records_to_insert = []
    try:
        with open(csv_file_path, "r", encoding="utf-8") as file_obj:
            reader = csv.DictReader(file_obj)
            for row in reader:
                first_seen = row["first_seen"] if row["first_seen"] != "Unknown" else None
                records_to_insert.append(
                    (
                        row["file_name"],
                        row["signature"],
                        row["file_type"],
                        first_seen,
                        row["file_type_mime"],
                        row["md5_hash"],
                        row["sha1_hash"],
                        row["sha256_hash"],
                        row["sha3_384_hash"],
                    )
                )
    except FileNotFoundError:
        log_error(f"Không tìm thấy file {csv_file_path}.")
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
            log_success(f"Đã thêm {len(records_to_insert)} records vào database.")
        except Exception as exc:
            conn.rollback()
            log_error(f"Lỗi khi thực hiện insert: {exc}")
        finally:
            cursor.close()
            conn.close()
            log_info("Đóng kết nối Database.")
    else:
        log_warn("Không có records nào để thêm vào database.")

def refresh_signature_files(json_output_file: Path, csv_output_file: Path) -> None:
    log_info("Bắt đầu tải dữ liệu signatures từ API...")

    if json_output_file.exists():
        log_info(f"Xóa file cũ: {json_output_file}")
        json_output_file.unlink()
    if csv_output_file.exists():
        log_info(f"Xóa file cũ: {csv_output_file}")
        csv_output_file.unlink()

    fetch_malware_signatures(output_file=str(json_output_file))
    if not json_output_file.exists():
        raise RuntimeError(
            f"Không tìm thấy file JSON output sau khi fetch: {json_output_file}"
        )

    log_success(f"Đã tải dữ liệu signatures: {json_output_file}")


def filter_and_import_signatures(json_output_file: Path, csv_output_file: Path) -> None:
    log_info("Bắt đầu lọc dữ liệu JSON sang CSV...")
    filter_malware_data(str(json_output_file), str(csv_output_file))
    if not csv_output_file.exists():
        raise RuntimeError(
            f"Không tìm thấy file CSV output sau khi filter: {csv_output_file}"
        )

    log_success(f"Đã tạo file CSV: {csv_output_file}")
    log_info("Bắt đầu import dữ liệu CSV vào PostgreSQL...")
    import_csv_to_db(str(csv_output_file))
    log_success("Hoàn tất import dữ liệu vào PostgreSQL.")


def run_data_pipeline(json_output_file: Path, csv_output_file: Path) -> None:
    refresh_signature_files(json_output_file, csv_output_file)
    filter_and_import_signatures(json_output_file, csv_output_file)
