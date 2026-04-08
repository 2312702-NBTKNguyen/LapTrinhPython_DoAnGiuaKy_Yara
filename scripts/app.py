from datetime import datetime
from pathlib import Path
import psycopg2
from common.utils import khoiTaoMoiTruong, ghiLogLoi, ghiLogInfo, ghiLogThanhCong, inMuc

from malware_scanner.reporting import hoanTatBaoCaoQuet, inTongKet
from malware_scanner.service import mayQuetMalware

from scripts.db_setup import thietLapDatabase
from scripts.pipeline import nhapSignatures

thuMucGoc = Path(__file__).resolve().parent.parent
jsonOutput = thuMucGoc / "data" / "malware_signatures.json"
rulesIndex = thuMucGoc / "rules" / "index.yar"

def khoiTaoHeThong() -> int:
    inMuc("CHẾ ĐỘ KHỞI CHẠY LẦN ĐẦU")

    try:
        khoiTaoMoiTruong()

        inMuc("THIẾT LẬP CƠ SỞ DỮ LIỆU")
        thietLapDatabase()

        inMuc("LÀM MỚI DỮ LIỆU SIGNATURES")
        nhapSignatures(jsonOutput)

        inMuc("HOÀN TẤT KHỞI CHẠY")
        ghiLogThanhCong("Hệ thống đã khởi tạo và làm mới dữ liệu signatures thành công.")
        return 0

    except (RuntimeError, ValueError, OSError, psycopg2.Error) as exc:
        print('-' * 100)
        ghiLogLoi(f"Khởi chạy thất bại: {exc}")
        return 1

def quetMucTieu(duongDanMucTieu: str | None = None) -> int:
    if not duongDanMucTieu:
        inMuc("CHẾ ĐỘ QUÉT")
        duongDanMucTieu = input("Nhập đường dẫn file hoặc thư mục cần quét: ").strip().strip('"\'')

    if not duongDanMucTieu:
        ghiLogLoi("Bạn chưa nhập đường dẫn để quét.")
        return 1

    mucTieuDaResolve = Path(duongDanMucTieu).expanduser().resolve()

    if not mucTieuDaResolve.exists():
        ghiLogLoi(f"Đường dẫn không tồn tại: {mucTieuDaResolve}")
        return 1

    scanner = mayQuetMalware(duongDanRules=str(rulesIndex))

    try:
        inMuc("MALWARE SCANNER - CHẾ ĐỘ QUÉT")
        ghiLogInfo(f"Target: {mucTieuDaResolve}")

        if mucTieuDaResolve.is_file():
            thoiDiemBatDau = datetime.now()
            scanner.quetMucTieu(str(mucTieuDaResolve))
            thoiGianQuet = (datetime.now() - thoiDiemBatDau).total_seconds()
            inTongKet(scanner.thongKeQuet, thoiGianQuet)
            hoanTatBaoCaoQuet(scanner.ketNoiDb, thoiDiemBatDau)
        else:
            scanner.quetThuMuc(str(mucTieuDaResolve))

        ghiLogThanhCong("Hoàn tất quét.")
        return 0
    finally:
        scanner.dongKetNoi()
