from __future__ import annotations

import csv
import json
import os

import pandas as pd
import psycopg2
import requests
from dotenv import load_dotenv
from psycopg2.extras import execute_values

from scripts.utils import get_db_connection_kwargs, log_error, log_info, log_success, log_warn


load_dotenv()


def fetch_malware_signatures(output_file: str = "./data/malware_signatures.json") -> None:
    url = "https://mb-api.abuse.ch/api/v1/"
    auth_key = os.getenv("MB_AUTH_KEY")

    # Danh sách các signatures phổ biến
    signatures_to_fetch = [
        # Nhóm Info Stealers (Mã độc đánh cắp thông tin)
        "RedLineStealer", "LokiBot", "AgentTesla", "Formbook",
        # Nhóm Banking Trojans & Botnets
        "Emotet", "TrickBot", "Mirai", "Dridex", 
        # Nhóm Ransomware (Mã độc tống tiền)
        "WannaCry", "LockBit", "Conti", "Ryuk",
        # Nhóm RATs (Remote Access Trojans - Trojan điều khiển từ xa)
        "RemcosRAT", "njRAT"
    ]
    malware_limit = 200

    if not auth_key:
        log_error("Chưa có API key trong file .env hoặc biến môi trường hệ thống.")
        return

    headers = {
        "Auth-Key": auth_key,
        "User-Agent": "Python-MalwareBazaar-Client/1.0",
    }

    log_info(
        f"Gửi request đến MalwareBazaar API với {len(signatures_to_fetch)} signatures..."
    )
    log_info(f"Danh sách các signatures: {', '.join(signatures_to_fetch)}")
    print("-" * 100)

    try:
        all_malware = []
        successful_signature_requests = 0
        failed_signature_requests = 0

        for signature in signatures_to_fetch:
            payload = {
                "query": "get_siginfo",
                "signature": signature,
                "limit": str(malware_limit),
            }

            log_info(f"Lấy dữ liệu cho signature: {signature}")
            try:
                response = requests.post(url, data=payload, headers=headers, timeout=60)
            except requests.exceptions.RequestException as exc:
                log_error(f"Signature {signature}: lỗi kết nối ({exc}), bỏ qua.")
                failed_signature_requests += 1
                continue

            if response.status_code == 401:
                log_error("401 Unauthorized: API key thiếu hoặc không hợp lệ.")
                return

            if response.status_code == 403:
                query_status = None
                try:
                    query_status = response.json().get("query_status")
                except ValueError:
                    pass

                if query_status:
                    log_error(f"403 Forbidden: truy cập bị từ chối ({query_status}).")
                return

            try:
                response.raise_for_status()
            except requests.exceptions.RequestException as exc:
                log_error(f"Signature {signature}: lỗi HTTP ({exc}), bỏ qua.")
                failed_signature_requests += 1
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
                successful_signature_requests += 1
                continue

            if query_status in ("no_results", "sig_not_found", "signature_not_found"):
                log_warn(f"Signature {signature}: không có dữ liệu ({query_status}).")
                successful_signature_requests += 1
                continue

            log_error(f"Signature {signature}: lỗi từ API ({query_status}).")
            failed_signature_requests += 1

        if successful_signature_requests == 0:
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
            f"Tổng kết: {successful_signature_requests} signature thành công, "
            f"{failed_signature_requests} signature lỗi."
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
        conn = psycopg2.connect(**get_db_connection_kwargs())
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
