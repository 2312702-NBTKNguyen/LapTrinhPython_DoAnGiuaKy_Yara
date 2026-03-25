import argparse
import sys

from scripts.workflows import (
    run_first_startup,
    run_interactive_mode,
    run_scan_once,
    run_update_pipeline,
)


DISPLAY_WIDTH = 100


def _center_title(text: str) -> str:
    return text.center(DISPLAY_WIDTH)


def print_project_info() -> None:
    bar = "=" * DISPLAY_WIDTH

    print(f"\n{bar}")
    print(_center_title("LẬP TRÌNH PYTHON - MALWARE SCANNER"))
    print(bar)
    print("Dự án quét mã độc theo 2 lớp phát hiện:")
    print("- Hash-based Detection: đối chiếu SHA256 với cơ sở dữ liệu mẫu độc hại")
    print("- YARA Pattern Matching: phát hiện hành vi/mẫu malware theo rule")

    print(f"\n{bar}")
    print(_center_title("CÁC LỆNH KHẢ DỤNG"))
    print(bar)
    print("1. Khởi chạy lần đầu: 'python main.py --run'")
    print("2. Cập nhật dữ liệu: 'python main.py --update'")
    print("3. Quét tự động 1 file/thư mục: 'python main.py --scan PATH'")
    print("4. Quét tương tác nhiều lần: 'python main.py --interactive'")
    print("5. Xem trợ giúp đầy đủ: 'python main.py -h'")


def build_parser() -> argparse.ArgumentParser:
    epilog = (
        "Ví dụ sử dụng:\n"
        "  python main.py --run\n"
        "  python main.py --update\n"
        "  python main.py --scan ./samples/test_emotet.txt\n"
        "  python main.py --scan ./samples\n"
        "  python main.py --interactive\n\n"
        "Gợi ý: Dùng --run cho lần đầu, sau đó dùng --update định kỳ trước khi quét."
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
        help="Khởi chạy lần đầu",
    )
    mode_group.add_argument(
        "-u",
        "--update",
        action="store_true",
        help="Cập nhật dữ liệu signatures",
    )
    mode_group.add_argument(
        "-s",
        "--scan",
        metavar="PATH",
        help="Quét 1 file/thư mục ở chế độ auto",
    )
    mode_group.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Mở chế độ CLI tương tác để nhập đường dẫn quét thủ công",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser()
    if not argv:
        print_project_info()
        return 0

    args = parser.parse_args(argv)

    if args.run:
        return run_first_startup()

    if args.update:
        return run_update_pipeline()

    if args.scan:
        return run_scan_once(args.scan)

    if args.interactive:
        return run_interactive_mode()

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
