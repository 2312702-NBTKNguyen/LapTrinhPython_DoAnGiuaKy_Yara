import json, requests
import pandas as pd
import psycopg2

from pathlib import Path
from collections.abc import Callable
from config import Config
from psycopg2.extras import execute_values


def _log(log_callback: Callable[[str], None] | None, message: str) -> None:
    if log_callback:
        log_callback(message)


def fetch_sigs(
    output_file: str = "./data/malware_signatures.json",
    log_callback: Callable[[str], None] | None = None,
) -> None:
    url = "https://mb-api.abuse.ch/api/v1/"
    auth_key = Config.MB_AUTH_KEY

    if not auth_key:
        message = "Chưa có API key trong file .env hoặc biến môi trường hệ thống."
        _log(log_callback, message)
        raise RuntimeError(message)

    headers = {
        "Auth-Key": auth_key,
        "User-Agent": "Python-MalwareBazaar-Client/1.0",
    }

    signatures = [
        "RedLineStealer", "LokiBot", "AgentTesla", "Formbook",
        "Emotet", "TrickBot", "Mirai", "Dridex",
        "WannaCry", "LockBit", "Conti", "Ryuk",
        "RemcosRAT", "njRAT",
    ]

    _log(log_callback, f"Gửi request đến MalwareBazaar API với {len(signatures)} signatures...")
    _log(log_callback, f"Danh sách các signatures: {', '.join(signatures)}")

    all_rows = []
    ok_count = 0
    err_count = 0

    for sig in signatures:
        payload = {
            "query": "get_siginfo",
            "signature": sig,
            "limit": 200,
        }

        _log(log_callback, f"Lấy dữ liệu signature: {sig}")
        try:
            response = requests.post(url, data=payload, headers=headers, timeout=60)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as exc:
            _log(log_callback, f"Signature {sig}: lỗi kết nối ({exc}), bỏ qua.")
            err_count += 1
            continue
        except ValueError:
            _log(log_callback, f"Signature {sig}: API trả về dữ liệu không phải JSON, bỏ qua.")
            err_count += 1
            continue

        status = data.get("query_status")
        if status == "ok":
            rows = data.get("data", [])
            _log(log_callback, f"Signature {sig}: nhận {len(rows)} records.")
            all_rows.extend(rows)
            ok_count += 1
            continue

        if status in ("no_results", "sig_not_found", "signature_not_found"):
            _log(log_callback, f"Signature {sig}: không có dữ liệu ({status}).")
            ok_count += 1
            continue

        _log(log_callback, f"Signature {sig}: lỗi từ API ({status}).")
        err_count += 1

    if ok_count == 0:
        message = "Không có request nào thành công."
        _log(log_callback, message)
        raise RuntimeError(message)

    uniq_rows = []
    seen = set()
    for row in all_rows:
        sha256 = row.get("sha256_hash")
        if sha256 in seen:
            continue
        if sha256:
            seen.add(sha256)
        uniq_rows.append(row)

    with open(output_file, "w", encoding="utf-8") as file_obj:
        json.dump(uniq_rows, file_obj, indent=4)

    _log(log_callback, f"Đã lưu {len(uniq_rows)} bản ghi vào '{output_file}'.")
    _log(log_callback, f"Đã lọc {len(all_rows) - len(uniq_rows)} bản ghi trùng lặp.")
    _log(log_callback, f"Tổng kết: {ok_count} request thành công, {err_count} request lỗi.")


def clean_json(
    input_file: str,
    log_callback: Callable[[str], None] | None = None,
) -> pd.DataFrame | None:
    _log(log_callback, f"Đọc dữ liệu từ file: {input_file}")
    try:
        df = pd.read_json(input_file)
        if df.empty:
            _log(log_callback, "File input rỗng, không có dữ liệu để xử lý.")
            return None

        columns = [
            "file_name", "signature", "file_type", "first_seen", "file_type_mime",
            "md5_hash", "sha1_hash", "sha256_hash", "sha3_384_hash",
        ]

        selected = {
            col: df[col] if col in df.columns else "Unknown"
            for col in columns
        }

        clean_df = pd.DataFrame(selected, columns=columns)
        clean_df.fillna("Unknown", inplace=True)
        _log(log_callback, "Đã chuẩn hóa dữ liệu JSON.")
        return clean_df

    except FileNotFoundError:
        _log(log_callback, f"Không tìm thấy file {input_file}.")
    except ValueError as exc:
        _log(log_callback, f"Lỗi khi đọc file JSON: {exc}")

    return None


def save_signatures(
    dataframe: pd.DataFrame,
    log_callback: Callable[[str], None] | None = None,
) -> None:
    _log(log_callback, "Bắt đầu nhập dữ liệu vào PostgreSQL...")

    try:
        conn = psycopg2.connect(
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            dbname=Config.DB_NAME,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
        )
        cursor = conn.cursor()
        _log(log_callback, "Kết nối Database thành công.")
    except (ValueError, psycopg2.Error) as exc:
        message = f"Lỗi Database khi kết nối: {exc}"
        _log(log_callback, message)
        raise RuntimeError(message) from exc

    rows = []
    for row in dataframe.to_dict(orient="records"):
        first_seen = row["first_seen"] if row["first_seen"] != "Unknown" else None
        rows.append(
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

    if not rows:
        _log(log_callback, "Không có bản ghi nào để thêm vào database.")
        cursor.close()
        conn.close()
        _log(log_callback, "Đóng kết nối Database.")
        return

    sql = """
        INSERT INTO malware_signatures (
            file_name, signature, file_type, first_seen, file_type_mime,
            md5_hash, sha1_hash, sha256_hash, sha3_384_hash
        ) VALUES %s
        ON CONFLICT (sha256_hash) DO NOTHING;
    """

    try:
        execute_values(cursor, sql, rows)
        conn.commit()
        _log(log_callback, f"Đã thêm {len(rows)} bản ghi vào database.")
    except psycopg2.Error as exc:
        conn.rollback()
        message = f"Lỗi Database khi thực hiện insert: {exc}"
        _log(log_callback, message)
        raise RuntimeError(message) from exc
    finally:
        cursor.close()
        conn.close()
        _log(log_callback, "Đóng kết nối Database.")


def sync_sigs(json_path: Path, log_callback: Callable[[str], None] | None = None) -> None:
    if json_path.exists():
        _log(log_callback, f"Xóa file cũ: {json_path}")
        json_path.unlink()

    fetch_sigs(output_file=str(json_path), log_callback=log_callback)
    if not json_path.exists():
        raise RuntimeError(f"Không tìm thấy file JSON sau khi fetch: {json_path}")

    _log(log_callback, f"Dữ liệu signatures được lưu tại: {json_path}")
    _log(log_callback, "-" * 100)

    _log(log_callback, "Bắt đầu lọc dữ liệu JSON.")
    clean_df = clean_json(str(json_path), log_callback=log_callback)
    if clean_df is None or clean_df.empty:
        raise RuntimeError(f"Không tạo được DataFrame hợp lệ từ file JSON: {json_path}")

    _log(log_callback, f"Đã tạo DataFrame với {len(clean_df)} bản ghi.")
    save_signatures(clean_df, log_callback=log_callback)
    _log(log_callback, "Hoàn tất nhập dữ liệu vào PostgreSQL.")
