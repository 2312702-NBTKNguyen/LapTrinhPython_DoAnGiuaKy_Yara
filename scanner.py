import sys

from main import main


if __name__ == "__main__":
    # Vào interactive mode.
    forwarded_args = sys.argv[1:] if len(sys.argv) > 1 else ["--interactive"]
    raise SystemExit(main(forwarded_args))