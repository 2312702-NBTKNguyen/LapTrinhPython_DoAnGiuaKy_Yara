"""
Tạo test samples cho archive scanning tests.

Tạo fake malware files với YARA-detectable patterns
và đóng gói vào ZIP archives.
"""

import os
import zipfile
import tempfile
from pathlib import Path


# Fake malware patterns khớp với YARA rules
FAKE_EMOTET = """MZ - Script Auto Update (Fake)
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "powershell -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA..."
Giao thức mạng sử dụng: Net.WebClient
Nguồn tải về: http://www.example-hacked-site.com/wp-content/plugins/mail/payload.exe
"""

FAKE_WANNACRY = """MZ - WannaCry Ransomware (Fake Test Sample)
iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
mssecsvc2.0
tasksche.exe
@WanaDecryptor@.exe
@Please_Read_Me@.txt
Oops, your files have been encrypted!
.WNCRY
"""

FAKE_LOCKBIT = """MZ - LockBit Ransomware (Fake Test Sample)
LockBit
Your files have been encrypted!
Contact us at: lockbit@example.com
Payment required in Bitcoin
"""

# Dữ liệu entropy cao để trigger phát hiện packed/encrypted
HIGH_ENTROPY_DATA = os.urandom(4096)


def create_test_files(output_dir: str):
    """Tạo fake malware test files."""
    os.makedirs(output_dir, exist_ok=True)

    # Tạo các file test riêng lẻ
    test_files = {
        "test_emotet.txt": FAKE_EMOTET,
        "test_wannacry.txt": FAKE_WANNACRY,
        "test_lockbit.txt": FAKE_LOCKBIT,
        "test_high_entropy.bin": HIGH_ENTROPY_DATA,
    }

    for filename, content in test_files.items():
        filepath = os.path.join(output_dir, filename)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(filepath, mode) as f:
            f.write(content)

    return list(test_files.keys())


def create_test_zip(zip_path: str, files_dir: str):
    """Tạo ZIP archive chứa test files."""
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename in os.listdir(files_dir):
            filepath = os.path.join(files_dir, filename)
            if os.path.isfile(filepath):
                zf.write(filepath, filename)

    print(f"Đã tạo ZIP: {zip_path}")
    print(f"  Files: {os.listdir(files_dir)}")


def create_nested_zip(output_path: str, files_dir: str):
    """Tạo ZIP chứa ZIP khác (nested archive)."""
    # Tạo inner ZIP trước
    inner_zip = os.path.join(files_dir, "inner.zip")
    with zipfile.ZipFile(inner_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("nested_malware.txt", FAKE_EMOTET)

    # Tạo outer ZIP chứa inner ZIP
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename in os.listdir(files_dir):
            filepath = os.path.join(files_dir, filename)
            if os.path.isfile(filepath):
                zf.write(filepath, filename)

    print(f"Đã tạo nested ZIP: {output_path}")


def main():
    """Tạo tất cả test samples."""
    # Tạo thư mục test
    samples_dir = Path("tests/samples")
    archives_dir = samples_dir / "archives"

    samples_dir.mkdir(parents=True, exist_ok=True)
    archives_dir.mkdir(parents=True, exist_ok=True)

    # Tạo temp directory để build archives
    with tempfile.TemporaryDirectory() as tmpdir:
        # Tạo test files
        print("Đang tạo test files...")
        files = create_test_files(tmpdir)

        # Tạo simple ZIP
        zip_path = archives_dir / "test_malware.zip"
        create_test_zip(str(zip_path), tmpdir)

        # Tạo nested ZIP
        nested_zip_path = archives_dir / "test_nested.zip"
        create_nested_zip(str(nested_zip_path), tmpdir)

    # Tạo test files trong thư mục samples (cho quét trực tiếp)
    print("\nĐang tạo test files trong thư mục samples...")
    for filename, content in {
        "test_emotet.txt": FAKE_EMOTET,
        "test_wannacry.txt": FAKE_WANNACRY,
        "test_lockbit.txt": FAKE_LOCKBIT,
    }.items():
        filepath = samples_dir / filename
        with open(filepath, "w") as f:
            f.write(content)
        print(f"  Đã tạo: {filepath}")

    print("\nHoàn thành! Đã tạo test samples:")
    print(f"  Archives: {archives_dir}")
    print(f"  Files trực tiếp: {samples_dir}")


if __name__ == "__main__":
    main()
