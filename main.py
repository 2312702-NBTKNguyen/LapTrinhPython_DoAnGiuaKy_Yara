import os, sys, argparse

from common.utils import canGiuaText
from scripts.app import khoiTaoHeThong, quetMucTieu

def xoaManHinh() -> None:
    os.system("cls" if os.name == "nt" else "clear")

def inThongTinDuAn() -> None:
    thanhNgang = "=" * 100

    print(f"\n{thanhNgang}")
    print(canGiuaText("LẬP TRÌNH PYTHON - MALWARE SCANNER", doRong=100))
    print(thanhNgang)

    print(f"\n{thanhNgang}")
    print(canGiuaText("CÁC LỆNH KHẢ DỤNG", doRong=100))
    print(thanhNgang)
    print("1. Khởi chạy lần đầu: 'python main.py --run'")
    print("2. Quét file/thư mục: 'python main.py --scan'")
    print("3. Xem trợ giúp đầy đủ: 'python main.py -h'")


def taoBoPhanTichThamSo() -> argparse.ArgumentParser:
    huongDanThem = (
        "Ví dụ sử dụng:\n"
        "  python main.py --run\n"
        "  python main.py --scan\n\n"
        "Gợi ý: Dùng --run để khởi tạo hoặc làm mới dữ liệu signatures trước khi quét."
    )

    boPhanTich = argparse.ArgumentParser(
        prog="main.py",
        epilog=huongDanThem,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    nhomCheDo = boPhanTich.add_mutually_exclusive_group(required=True)
    nhomCheDo.add_argument(
        "--run",
        action="store_true",
        help="Khởi tạo hệ thống và làm mới dữ liệu signatures",
    )
    nhomCheDo.add_argument(
        "-s",
        "--scan",
        action="store_true",
        help="Nhập đường dẫn file/thư mục và quét",
    )

    return boPhanTich


def chuongTrinhChinh(danhSachThamSo: list[str] | None = None) -> int:
    if danhSachThamSo is None:
        danhSachThamSo = sys.argv[1:]

    xoaManHinh()

    boPhanTich = taoBoPhanTichThamSo()
    if not danhSachThamSo:
        inThongTinDuAn()
        return 0

    thamSoDaPhanTich = boPhanTich.parse_args(danhSachThamSo)

    if thamSoDaPhanTich.run:
        return khoiTaoHeThong()

    if thamSoDaPhanTich.scan:
        return quetMucTieu()

    boPhanTich.print_help()
    return 1

if __name__ == "__main__":
    raise SystemExit(chuongTrinhChinh(sys.argv[1:]))
