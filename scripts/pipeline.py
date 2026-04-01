from __future__ import annotations

from pathlib import Path

from scripts.data_sources import (
    fetch_malware_signatures,
    filter_malware_data,
    import_csv_to_db,
)
from scripts.utils import log_info, log_success


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
