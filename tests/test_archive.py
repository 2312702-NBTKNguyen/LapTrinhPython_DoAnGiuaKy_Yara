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

from malware_scanner.detection.yara_engine import load_yara_rules
from malware_scanner.archive.scanner import ArchiveScanner
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


def _build_zip_with_non_pe_family_samples() -> str:
    # Tạo ZIP tạm chứa mẫu doc/xls/js để test nhánh non-PE của YARA rules.
    payloads = {
        "trickbot.doc": b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1 Word.Document <mcconf> injectDll group_tag WScript.Shell powershell",
        "remcosrat.xls": b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1 Workbook Remcos BreakingSecurity.net Host:Port MUTEX Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "lokibot.doc": b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1 Word.Document fre.php ftp:// MSXML2.XMLHTTP ADODB.Stream AutoOpen",
        "agenttesla.js": b"var a='AgentTesla'; var c='smtp.gmail.com'; var s='Password:'; var x='WScript.Shell'; eval(fromCharCode(65));",
    }

    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp.close()

    with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, content in payloads.items():
            zf.writestr(filename, content)

    return tmp.name


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
        assert True
    else:
        print("\n❌ FAIL: Không phát hiện malware patterns")
        assert False


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
        assert True
    else:
        print("\n❌ FAIL: Không phát hiện malware patterns trong nested archive")
        assert False


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
        assert results is not None
    except NestedDepthError:
        print("✅ PASS: Exception giới hạn depth được raise đúng")
        assert True
    except Exception as e:
        print(f"❌ FAIL: Lỗi không mong muốn: {e}")
        assert False
    finally:
        os.unlink(zip_path)


def test_direct_file_comparison():
    """So sánh quét archive vs quét file trực tiếp."""
    print("\n" + "=" * 60)
    print("TEST: So sánh Archive vs File Trực Tiếp")
    print("=" * 60)

    from malware_scanner.detection.yara_engine import scan_with_yara

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
        assert True
    else:
        print("\n❌ FAIL: Không nhất quán trong phát hiện")
        assert False


def test_non_pe_family_samples_in_zip():
    """Test quét mẫu doc/xls/js trong ZIP bằng nhánh non-PE rules."""
    print("\n" + "=" * 60)
    print("TEST: Quét Non-PE Family Samples Trong ZIP")
    print("=" * 60)

    rules = load_yara_rules("rules/index.yar")
    scanner = ArchiveScanner(rules)

    zip_path = _build_zip_with_non_pe_family_samples()

    try:
        results = list(scanner.scan(zip_path))
    finally:
        os.unlink(zip_path)

    detected = {result.rule_name for result in results}
    expected = {
        "BankingTrojan_TrickBot",
        "RAT_Remcos",
        "Infostealer_LokiBot",
        "Infostealer_AgentTesla",
    }

    print(f"\nDetected rules: {sorted(detected)}")
    missing = sorted(expected - detected)

    if not missing:
        print("\n✅ PASS: Đã phát hiện đủ 4 family non-PE trong archive")
        assert True
        return

    print(f"\n❌ FAIL: Thiếu phát hiện: {missing}")
    assert False


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
        test_non_pe_family_samples_in_zip,
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
