"""
Generate test samples for archive scanning tests.

Creates fake malware files with YARA-detectable patterns
and packages them into ZIP archives.
"""

import os
import zipfile
import tempfile
from pathlib import Path


# Fake malware patterns that match our YARA rules
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

# High entropy data to trigger packed/encrypted detection
HIGH_ENTROPY_DATA = os.urandom(4096)


def create_test_files(output_dir: str):
    """Create fake malware test files."""
    os.makedirs(output_dir, exist_ok=True)

    # Create individual test files
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
    """Create ZIP archive containing test files."""
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename in os.listdir(files_dir):
            filepath = os.path.join(files_dir, filename)
            if os.path.isfile(filepath):
                zf.write(filepath, filename)

    print(f"Created ZIP: {zip_path}")
    print(f"  Files: {os.listdir(files_dir)}")


def create_nested_zip(output_path: str, files_dir: str):
    """Create ZIP containing another ZIP (nested archive)."""
    # First create inner ZIP
    inner_zip = os.path.join(files_dir, "inner.zip")
    with zipfile.ZipFile(inner_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("nested_malware.txt", FAKE_EMOTET)

    # Create outer ZIP containing inner ZIP
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename in os.listdir(files_dir):
            filepath = os.path.join(files_dir, filename)
            if os.path.isfile(filepath):
                zf.write(filepath, filename)

    print(f"Created nested ZIP: {output_path}")


def main():
    """Generate all test samples."""
    # Create test directories
    samples_dir = Path("tests/samples")
    archives_dir = samples_dir / "archives"

    samples_dir.mkdir(parents=True, exist_ok=True)
    archives_dir.mkdir(parents=True, exist_ok=True)

    # Create temp directory for building archives
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        print("Creating test files...")
        files = create_test_files(tmpdir)

        # Create simple ZIP
        zip_path = archives_dir / "test_malware.zip"
        create_test_zip(str(zip_path), tmpdir)

        # Create nested ZIP
        nested_zip_path = archives_dir / "test_nested.zip"
        create_nested_zip(str(nested_zip_path), tmpdir)

    # Also create test files in samples directory (for direct scanning)
    print("\nCreating test files in samples directory...")
    for filename, content in {
        "test_emotet.txt": FAKE_EMOTET,
        "test_wannacry.txt": FAKE_WANNACRY,
        "test_lockbit.txt": FAKE_LOCKBIT,
    }.items():
        filepath = samples_dir / filename
        with open(filepath, "w") as f:
            f.write(content)
        print(f"  Created: {filepath}")

    print("\nDone! Test samples created:")
    print(f"  Archives: {archives_dir}")
    print(f"  Direct files: {samples_dir}")


if __name__ == "__main__":
    main()
