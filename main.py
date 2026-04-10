import argparse
import os
import sys

from malware_scanner.utils import center_text
from app import boot, scan

def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")

def show_info() -> None:
    bar = "=" * 100

    print(f"\n{bar}")
    print(center_text("LẬP TRÌNH PYTHON - MALWARE SCANNER", width=100))
    print(bar)

    print(f"\n{bar}")
    print(center_text("CHẾ ĐỘ MẶC ĐỊNH", width=100))
    print(bar)
    print("1. Mở GUI: 'python main.py'")
    print("2. Khởi tạo dữ liệu bằng CLI: 'python main.py --run'")
    print("3. Quét bằng CLI: 'python main.py --scan <path>'")
    print("4. Xem trợ giúp đầy đủ: 'python main.py -h'")


def make_parser() -> argparse.ArgumentParser:
    epilog = (
        "Ví dụ sử dụng:\n"
        "  python main.py\n"
        "  python main.py --run\n"
        "  python main.py --scan /path/to/target\n\n"
        "Gợi ý: Chạy không tham số để mở GUI CustomTkinter (Windows-first)."
    )

    parser = argparse.ArgumentParser(
        prog="main.py",
        epilog=epilog,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    mode_group = parser.add_mutually_exclusive_group(required=False)
    mode_group.add_argument(
        "-r",
        "--run",
        action="store_true",
        help="Khởi tạo hệ thống và làm mới dữ liệu signatures",
    )
    mode_group.add_argument(
        "-s",
        "--scan",
        metavar="TARGET",
        help="Quét file/thư mục bằng CLI",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    clear()

    parser = make_parser()
    if not argv:
        from gui.main_window import run as run_gui
        run_gui()
        return 0

    args = parser.parse_args(argv)

    if args.run:
        return boot()

    if args.scan:
        return scan(args.scan)

    show_info()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
