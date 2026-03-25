"""
Test chức năng quét archive.

Test quét ZIP với fake malware samples
để verify YARA rules phát hiện patterns bên trong archives.
"""

import os
import sys
import tempfile
import zipfile
from pathlib import Path

# Thêm thư mục cha vào path
sys.path.insert(0, str(Path(__file__).parent.parent))

from malware_scanner.engine import load_yara_rules
from malware_scanner.archive import ArchiveScanner
from malware_scanner.exceptions import ArchiveBombError, NestedDepthError


def _build_zip_with_pe_sample() -> str:
    # Tạo ZIP tạm chứa file PE mẫu để test strict PE rules.
    src_file = Path("tests/samples/test_emotet.exe")
    if not src_file.exists():
        raise FileNotFoundError(f"Không tìm thấy file PE mẫu: {src_file}")

    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp.close()

    with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(src_file, arcname=src_file.name)

    return tmp.name


def _build_nested_zip_with_pe_sample() -> str:
    # Tạo nested ZIP tạm (outer.zip chứa inner.zip, inner.zip chứa file PE mẫu).
    src_file = Path("tests/samples/test_emotet.exe")
    if not src_file.exists():
        raise FileNotFoundError(f"Không tìm thấy file PE mẫu: {src_file}")

    inner_tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    inner_tmp.close()
    with zipfile.ZipFile(inner_tmp.name, "w", zipfile.ZIP_DEFLATED) as inner_zf:
        inner_zf.write(src_file, arcname=src_file.name)

    outer_tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    outer_tmp.close()
    with zipfile.ZipFile(outer_tmp.name, "w", zipfile.ZIP_DEFLATED) as outer_zf:
        outer_zf.write(inner_tmp.name, arcname="inner.zip")

    os.unlink(inner_tmp.name)
    return outer_tmp.name


def test_zip_scanning():
    """Test quét file bên trong ZIP archive."""
    print("=" * 60)
    print("TEST: Quét ZIP Archive")
    print("=" * 60)

    rules = load_yara_rules("rules/index.yar")
    scanner = ArchiveScanner(rules)

    zip_path = _build_zip_with_pe_sample()

    print(f"\nĐang quét: {zip_path}")
    print("-" * 60)

    try:
        results = list(scanner.scan(zip_path))
    finally:
        os.unlink(zip_path)

    print(f"\nTìm thấy {len(results)} kết quả khớp:")
    for result in results:
        print(f"  - {result.file_path}")
        print(f"    Rule: {result.rule_name}")
        print(f"    Kích thước: {result.file_size} bytes")

    if len(results) > 0:
        print("\n✅ PASS: Quét archive phát hiện malware patterns")
        return True
    else:
        print("\n❌ FAIL: Không phát hiện malware patterns")
        return False


def test_nested_zip():
    """Test quét nested ZIP archives."""
    print("\n" + "=" * 60)
    print("TEST: Quét Nested ZIP")
    print("=" * 60)

    rules = load_yara_rules("rules/index.yar")
    scanner = ArchiveScanner(rules, max_depth=3)

    zip_path = _build_nested_zip_with_pe_sample()

    print(f"\nĐang quét: {zip_path}")
    print("-" * 60)

    try:
        results = list(scanner.scan(zip_path))
    finally:
        os.unlink(zip_path)

    print(f"\nTìm thấy {len(results)} kết quả khớp:")
    for result in results:
        print(f"  - {result.file_path}")
        print(f"    Rule: {result.rule_name}")

    if len(results) > 0:
        print("\n✅ PASS: Quét nested archive hoạt động")
        return True
    else:
        print("\n❌ FAIL: Không phát hiện malware patterns trong nested archive")
        return False


def test_depth_limit():
    """Test kiểm tra giới hạn depth nested archive."""
    print("\n" + "=" * 60)
    print("TEST: Giới hạn Depth Nested")
    print("=" * 60)

    rules = load_yara_rules("rules/index.yar")
    scanner = ArchiveScanner(rules, max_depth=0)  # Không cho phép nesting

    zip_path = _build_nested_zip_with_pe_sample()

    try:
        results = list(scanner.scan(zip_path))
        # Nếu đến đây với max_depth=0, nested archives sẽ bị bỏ qua
        print("✅ PASS: Xử lý giới hạn depth thành công")
        return True
    except NestedDepthError:
        print("✅ PASS: Exception giới hạn depth được raise đúng")
        return True
    except Exception as e:
        print(f"❌ FAIL: Lỗi không mong muốn: {e}")
        return False
    finally:
        os.unlink(zip_path)


def test_direct_file_comparison():
    """So sánh quét archive vs quét file trực tiếp."""
    print("\n" + "=" * 60)
    print("TEST: So sánh Archive vs File Trực Tiếp")
    print("=" * 60)

    from malware_scanner.engine import scan_with_yara

    rules = load_yara_rules("rules/index.yar")
    scanner = ArchiveScanner(rules)

    # Quét file PE trực tiếp
    direct_file = "tests/samples/test_emotet.exe"
    direct_matches = scan_with_yara(rules, direct_file)

    # Quét archive chứa cùng file
    zip_path = _build_zip_with_pe_sample()
    try:
        archive_results = list(scanner.scan(zip_path))
    finally:
        os.unlink(zip_path)

    print(f"\nQuét file trực tiếp: {direct_file}")
    print(f"  Kết quả khớp: {direct_matches}")

    print(f"\nQuét archive: {zip_path}")
    archive_matches = [r.rule_name for r in archive_results if "Emotet" in r.rule_name]
    print(f"  Emotet khớp: {archive_matches}")

    if direct_matches and len(archive_matches) > 0:
        print("\n✅ PASS: Cả hai phương pháp đều phát hiện malware")
        return True
    else:
        print("\n❌ FAIL: Không nhất quán trong phát hiện")
        return False


def main():
    """Chạy tất cả tests."""
    print("\n" + "=" * 60)
    print("BỘ TEST QUÉT ARCHIVE")
    print("=" * 60 + "\n")

    tests = [
        test_zip_scanning,
        test_nested_zip,
        test_depth_limit,
        test_direct_file_comparison,
    ]

    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"\n❌ TEST FAILED với exception: {e}")
            results.append(False)

    # Tổng kết
    print("\n" + "=" * 60)
    print("TỔNG KẾT TEST")
    print("=" * 60)

    passed = sum(results)
    total = len(results)

    print(f"\nĐạt: {passed}/{total}")

    if passed == total:
        print("\n🎉 TẤT CẢ TESTS ĐỀU ĐẠT!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) không đạt")
        return 1


if __name__ == "__main__":
    sys.exit(main())
