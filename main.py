import argparse
import os
import sys

from common.utils import center_text
from scripts.app import init_system, scan_target

def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")

def print_project_info() -> None:
    bar = "=" * 100

    print(f"\n{bar}")
    print(center_text("LẬP TRÌNH PYTHON - MALWARE SCANNER", width=100))
    print(bar)

    print(f"\n{bar}")
    print(center_text("CÁC LỆNH KHẢ DỤNG", width=100))
    print(bar)
    print("1. Khởi chạy lần đầu: 'python main.py --run'")
    print("2. Quét file/thư mục: 'python main.py --scan'")
    print("3. Xem trợ giúp đầy đủ: 'python main.py -h'")


def build_parser() -> argparse.ArgumentParser:
    epilog = (
        "Ví dụ sử dụng:\n"
        "  python main.py --run\n"
        "  python main.py --scan\n\n"
        "Gợi ý: Dùng --run để khởi tạo hoặc làm mới dữ liệu signatures trước khi quét."
    )

    parser = argparse.ArgumentParser(
        prog="main.py",
        epilog=epilog,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--run",
        action="store_true",
        help="Khởi tạo hệ thống và làm mới dữ liệu signatures",
    )
    mode_group.add_argument(
        "-s",
        "--scan",
        action="store_true",
        help="Nhập đường dẫn file/thư mục và quét",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    clear_screen()

    parser = build_parser()
    if not argv:
        print_project_info()
        return 0

    args = parser.parse_args(argv)

    if args.run:
        return init_system()

    if args.scan:
        return scan_target()

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
