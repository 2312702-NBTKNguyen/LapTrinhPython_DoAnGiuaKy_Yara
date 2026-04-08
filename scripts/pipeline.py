import json, os, requests
import pandas as pd
import psycopg2

from pathlib import Path
from common.utils import taoKetNoiDb, khoiTaoMoiTruong, ghiLogLoi, ghiLogInfo, ghiLogThanhCong, ghiLogCanhBao
from psycopg2.extras import execute_values


def layMalwareSignatures(outputFile: str = "./data/malware_signatures.json") -> None:
    url = "https://mb-api.abuse.ch/api/v1/"
    authKey = os.getenv("MB_AUTH_KEY")

    if not authKey:
        thongDiep = "Chưa có API key trong file .env hoặc biến môi trường hệ thống."
        ghiLogLoi(thongDiep)
        raise RuntimeError(thongDiep)

    headers = {
        "Auth-Key": authKey,
        "User-Agent": "Python-MalwareBazaar-Client/1.0",
    }

    # Danh sách các signatures phổ biến
    signatures = [
        # Nhóm Info Stealers (Mã độc đánh cắp thông tin)
        "RedLineStealer", "LokiBot", "AgentTesla", "Formbook",
        # Nhóm Banking Trojans & Botnets
        "Emotet", "TrickBot", "Dridex", "Mirai",
        # Nhóm Ransomware (Mã độc tống tiền)
        "WannaCry", "LockBit", "Conti", "Ryuk",
        # Nhóm RATs (Remote Access Trojans - Trojan điều khiển từ xa)
        "RemcosRAT", "njRAT"
    ]    

    ghiLogInfo(f"Gửi request đến MalwareBazaar API với {len(signatures)} signatures...")
    ghiLogInfo(f"Danh sách các signatures: {', '.join(signatures)}")
    tatCaMalware = []
    soRequestThanhCong = 0
    soRequestLoi = 0

    for sig in signatures:
        duLieuJson = laySignature(sig, url, headers)
        if duLieuJson is None:
            soRequestLoi += 1
            continue

        trangThaiQuery = duLieuJson.get("query_status")
        if trangThaiQuery == "ok":
            danhSachRecordSignature = duLieuJson.get("data", [])
            ghiLogThanhCong(f"Signature {sig}: nhận {len(danhSachRecordSignature)} records.")
            tatCaMalware.extend(danhSachRecordSignature)
            soRequestThanhCong += 1
            continue

        if trangThaiQuery in ("no_results", "sig_not_found", "signature_not_found"):
            ghiLogCanhBao(f"Signature {sig}: không có dữ liệu ({trangThaiQuery}).")
            soRequestThanhCong += 1
            continue

        ghiLogLoi(f"Signature {sig}: lỗi từ API ({trangThaiQuery}).")
        soRequestLoi += 1

    if soRequestThanhCong == 0:
        thongDiep = "Không có request nào thành công."
        ghiLogLoi(thongDiep)
        raise RuntimeError(thongDiep)

    malwareKhongTrungLap = []
    hashDaThay = set()
    for banGhi in tatCaMalware:
        sha256Hash = banGhi.get("sha256_hash")
        if sha256Hash in hashDaThay:
            continue

        if sha256Hash:
            hashDaThay.add(sha256Hash)
        malwareKhongTrungLap.append(banGhi)

    with open(outputFile, "w", encoding="utf-8") as fileObj:
        json.dump(malwareKhongTrungLap, fileObj, indent=4)

    ghiLogThanhCong(f"Đã lưu {len(malwareKhongTrungLap)} bản ghi vào '{outputFile}'.")
    ghiLogInfo(f"Đã lọc {len(tatCaMalware) - len(malwareKhongTrungLap)} bản ghi trùng lặp.")
    ghiLogInfo(f"Tổng kết: {soRequestThanhCong} request thành công, " f"{soRequestLoi} request lỗi.")

def laySignature(sig: str, url: str, headers: dict[str, str]) -> dict | None:
    payload = {
        "query": "get_siginfo",
        "signature": sig,
        "limit": 500,
    }

    ghiLogInfo(f"Lấy dữ liệu signature: {sig}")
    try:
        response = requests.post(url, data=payload, headers=headers, timeout=60)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as exc:
        ghiLogLoi(f"Signature {sig}: lỗi kết nối ({exc}), bỏ qua.")
    except ValueError:
        ghiLogCanhBao(
            f"Signature {sig}: API trả về dữ liệu không phải JSON, bỏ qua."
        )

    return None

def _dinhDangLoiDb(hanhDong: str, exc: Exception) -> str:
    return f"Lỗi Database khi {hanhDong}: {exc}"


def _nemLoiRuntimeDb(hanhDong: str, exc: Exception) -> None:
    thongDiep = _dinhDangLoiDb(hanhDong, exc)
    ghiLogLoi(thongDiep)
    raise RuntimeError(thongDiep) from exc

def locDuLieuMalware(inputFile: str) -> pd.DataFrame | None:
    ghiLogInfo(f"Đọc dữ liệu từ file: {inputFile}")

    try:
        bangDuLieu = pd.read_json(inputFile)
        if bangDuLieu.empty:
            ghiLogCanhBao("File input rỗng, không có dữ liệu để xử lý.")
            return None

        columns = [
            "file_name", "signature", "file_type", "first_seen", "file_type_mime",
            "md5_hash", "sha1_hash", "sha256_hash", "sha3_384_hash"
        ]

        duLieuDaChon = {}
        for col in columns:
            if col in bangDuLieu.columns:
                duLieuDaChon[col] = bangDuLieu[col]
            else:
                duLieuDaChon[col] = "Unknown"

        duLieuDaLamSach = pd.DataFrame(duLieuDaChon, columns=columns)
        duLieuDaLamSach.fillna("Unknown", inplace=True)
        ghiLogThanhCong("Đã chuẩn hóa dữ liệu JSON.")
        return duLieuDaLamSach

    except FileNotFoundError:
        ghiLogLoi(f"Không tìm thấy file {inputFile}.")
    except ValueError as exc:
        ghiLogLoi(f"Lỗi khi đọc file JSON: {exc}")

    return None

def nhapDuLieuVaoDatabase(dataframe: pd.DataFrame) -> None:
    ghiLogInfo("Bắt đầu nhập dữ liệu vào PostgreSQL...")

    try:
        ketNoiDb = taoKetNoiDb()
        conTro = ketNoiDb.cursor()
        ghiLogThanhCong("Kết nối Database thành công.")
    except (ValueError, psycopg2.Error) as exc:
        _nemLoiRuntimeDb("kết nối", exc)

    banGhiCanThem = []
    for row in dataframe.to_dict(orient="records"):
        firstSeen = row["first_seen"] if row["first_seen"] != "Unknown" else None
        banGhiCanThem.append(
            (row["file_name"], row["signature"], row["file_type"], firstSeen, row["file_type_mime"], row["md5_hash"], row["sha1_hash"], row["sha256_hash"], row["sha3_384_hash"])
        )

    if not banGhiCanThem:
        ghiLogCanhBao("Không có bản ghi nào để thêm vào database.")
        conTro.close()
        ketNoiDb.close()
        ghiLogInfo("Đóng kết nối Database.")
        return

    insertQuery = """
        INSERT INTO malware_signatures (
            file_name, signature, file_type, first_seen, file_type_mime,
            md5_hash, sha1_hash, sha256_hash, sha3_384_hash
        ) VALUES %s
        ON CONFLICT (sha256_hash) DO NOTHING;
    """

    try:
        execute_values(conTro, insertQuery, banGhiCanThem)
        ketNoiDb.commit()
        ghiLogThanhCong(f"Đã thêm {len(banGhiCanThem)} bản ghi vào database.")
    except psycopg2.Error as exc:
        ketNoiDb.rollback()
        _nemLoiRuntimeDb("thực hiện insert", exc)
    finally:
        conTro.close()
        ketNoiDb.close()
        ghiLogInfo("Đóng kết nối Database.")

def nhapSignatures(jsonOutputFile: Path) -> None:
    khoiTaoMoiTruong()
    if jsonOutputFile.exists():
        ghiLogInfo(f"Xóa file cũ: {jsonOutputFile}")
        jsonOutputFile.unlink()

    layMalwareSignatures(outputFile=str(jsonOutputFile))
    if not jsonOutputFile.exists():
        raise RuntimeError(
            f"Không tìm thấy file JSON sau khi fetch: {jsonOutputFile}"
        )

    ghiLogThanhCong(f"Dữ liệu signatures được lưu tại: {jsonOutputFile}")
    ghiLogInfo("-" * 100)

    ghiLogInfo("Bắt đầu lọc dữ liệu JSON.")
    duLieuDaLamSach = locDuLieuMalware(str(jsonOutputFile))
    if duLieuDaLamSach is None or duLieuDaLamSach.empty:
        raise RuntimeError(
            f"Không tạo được DataFrame hợp lệ từ file JSON: {jsonOutputFile}"
        )

    ghiLogThanhCong(f"Đã tạo DataFrame với {len(duLieuDaLamSach)} bản ghi.")
    nhapDuLieuVaoDatabase(duLieuDaLamSach)
    ghiLogThanhCong("Hoàn tất nhập dữ liệu vào PostgreSQL.")
