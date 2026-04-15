import json
import sqlite3
import requests

from pathlib import Path
from collections.abc import Callable

from config import Config
from data_tools import _log
from data_tools.db_setup import connect_db

COLUMNS = [
    "file_name", "signature", "file_type", "first_seen", "file_type_mime",
    "md5_hash", "sha1_hash", "sha256_hash", "sha3_384_hash",
]

SIGNATURES = [
    # --- Nhóm Infostealer (Đánh cắp thông tin) ---
    "AgentTesla", "Formbook", "LokiBot",
    "RedLineStealer", "RaccoonStealer",
    # --- Nhóm Banking Trojan (Trojan ngân hàng) ---
    "Dridex", "Emotet", "TrickBot", "IcedID",
    # --- Nhóm Ransomware (Mã độc tống tiền) ---
    "WannaCry", "LockBit", "Conti", "Ryuk", "BlackCat",
    # --- Nhóm RAT (Trojan điều khiển từ xa) ---
    "RemcosRAT", "njRAT", "AsyncRAT", "DarkComet",
    # --- Nhóm Botnet ---
    "Mirai",
    # --- Nhóm Framework (Công cụ tấn công) ---
    "CobaltStrike",
]


def fetch_sigs(
    output_file: str = "./data/malware_signatures.json",
    log_callback: Callable[[str], None] | None = None,
) -> None:
    url = "https://mb-api.abuse.ch/api/v1/"
    auth_key = Config.MB_AUTH_KEY

    if not auth_key:
        raise RuntimeError("Chưa có API key trong file .env hoặc biến môi trường hệ thống.")

    headers = {
        "Auth-Key": auth_key,
        "User-Agent": "Python-MalwareBazaar-Client/1.0",
    }

    _log(log_callback, f"Bắt đầu đồng bộ signatures từ MalwareBazaar ({len(SIGNATURES)} signatures).")
    _log(log_callback, f"Danh sách các signatures: {', '.join(SIGNATURES)}")


    all_rows = []
    ok_count = 0
    err_count = 0

    for sig in SIGNATURES:
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
            _log(log_callback, f"Signature {sig}: không tìm thấy dữ liệu ({status}).")
            ok_count += 1
            continue

        _log(log_callback, f"Signature {sig}: lỗi từ API ({status}).")
        err_count += 1

    if ok_count == 0:
        raise RuntimeError(f"Không có request nào thành công.")

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


def _parse_json(input_file: str, log_callback: Callable[[str], None] | None = None) -> list[tuple]:
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        _log(log_callback, f"Không tìm thấy file {input_file}.")
        return []
    except (ValueError, json.JSONDecodeError) as exc:
        _log(log_callback, f"Lỗi khi đọc file JSON: {exc}")
        return []

    if not raw:
        _log(log_callback, "File input rỗng, không có dữ liệu để xử lý.")
        return []

    rows = []
    for item in raw:
        first_seen = item.get("first_seen") or None
        rows.append(tuple(
            first_seen if col == "first_seen" else (item.get(col) or "Unknown")
            for col in COLUMNS
        ))

    return rows


def _import_db(rows: list[tuple], log_callback: Callable[[str], None] | None = None) -> None:
    if not rows:
        return

    try:
        conn = connect_db()
    except sqlite3.Error as exc:
        _log(log_callback, f"Lỗi CSDL khi kết nối: {exc}")
        return

    sql = """
        INSERT OR IGNORE INTO malware_signatures (
            file_name, signature, file_type, first_seen, file_type_mime,
            md5_hash, sha1_hash, sha256_hash, sha3_384_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    try:
        conn.executemany(sql, rows)
        conn.commit()
    except sqlite3.Error as exc:
        conn.rollback()
        _log(log_callback, f"Lỗi CSDL khi insert: {exc}")
    finally:
        conn.close()


def sync_sigs(json_path: Path, log_callback: Callable[[str], None] | None = None) -> None:
    if json_path.exists():
        json_path.unlink()

    fetch_sigs(output_file=str(json_path), log_callback=log_callback)
    if not json_path.exists():
        raise RuntimeError(f"Không tìm thấy file JSON sau khi fetch: {json_path}")

    rows = _parse_json(str(json_path), log_callback=log_callback)
    if not rows:
        raise RuntimeError(f"Không tạo được dữ liệu hợp lệ từ file JSON: {json_path}")

    _import_db(rows, log_callback=log_callback)
    _log(log_callback, f"Đồng bộ signatures thành công: {len(rows)} bản ghi hợp lệ.")
