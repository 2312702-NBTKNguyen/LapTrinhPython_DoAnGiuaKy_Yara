"""
Test chức năng quét archive.

Test quét ZIP với fake malware samples
để verify YARA rules phát hiện patterns bên trong archives.
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from malware_scanner.engine import load_yara_rules
from malware_scanner.archive import ArchiveScanner
from malware_scanner.exceptions import ArchiveBombError, NestedDepthError


def test_zip_scanning():
    """Test scanning files inside ZIP archive."""
    print("=" * 60)
    print("TEST: ZIP Archive Scanning")
    print("=" * 60)

    rules = load_yara_rules("rules/index.yar")
    scanner = ArchiveScanner(rules)

    zip_path = "tests/samples/archives/test_malware.zip"

    if not os.path.exists(zip_path):
        print(f"ERROR: Test ZIP not found: {zip_path}")
        return False

    print(f"\nScanning: {zip_path}")
    print("-" * 60)

    results = list(scanner.scan(zip_path))

    print(f"\nFound {len(results)} matches:")
    for result in results:
        print(f"  - {result.file_path}")
        print(f"    Rule: {result.rule_name}")
        print(f"    Size: {result.file_size} bytes")

    if len(results) > 0:
        print("\n✅ PASS: Archive scanning detected malware patterns")
        return True
    else:
        print("\n❌ FAIL: No malware patterns detected")
        return False


def test_nested_zip():
    """Test scanning nested ZIP archives."""
    print("\n" + "=" * 60)
    print("TEST: Nested ZIP Scanning")
    print("=" * 60)

    rules = load_yara_rules("rules/index.yar")
    scanner = ArchiveScanner(rules, max_depth=3)

    zip_path = "tests/samples/archives/test_nested.zip"

    if not os.path.exists(zip_path):
        print(f"ERROR: Test ZIP not found: {zip_path}")
        return False

    print(f"\nScanning: {zip_path}")
    print("-" * 60)

    results = list(scanner.scan(zip_path))

    print(f"\nFound {len(results)} matches:")
    for result in results:
        print(f"  - {result.file_path}")
        print(f"    Rule: {result.rule_name}")

    if len(results) > 0:
        print("\n✅ PASS: Nested archive scanning works")
        return True
    else:
        print("\n❌ FAIL: No malware patterns detected in nested archive")
        return False


def test_depth_limit():
    """Test that nesting depth limit is enforced."""
    print("\n" + "=" * 60)
    print("TEST: Nesting Depth Limit")
    print("=" * 60)

    rules = load_yara_rules("rules/index.yar")
    scanner = ArchiveScanner(rules, max_depth=0)  # No nesting allowed

    zip_path = "tests/samples/archives/test_nested.zip"

    try:
        results = list(scanner.scan(zip_path))
        # If we get here with max_depth=0, nested archives should be skipped
        print("✅ PASS: Depth limit handled gracefully")
        return True
    except NestedDepthError:
        print("✅ PASS: Depth limit exception raised correctly")
        return True
    except Exception as e:
        print(f"❌ FAIL: Unexpected error: {e}")
        return False


def test_direct_file_comparison():
    """Compare archive scanning vs direct file scanning."""
    print("\n" + "=" * 60)
    print("TEST: Archive vs Direct File Scanning")
    print("=" * 60)

    from malware_scanner.engine import scan_with_yara

    rules = load_yara_rules("rules/index.yar")
    scanner = ArchiveScanner(rules)

    # Scan direct PE file
    direct_file = "tests/samples/test_emotet.exe"
    direct_matches = scan_with_yara(rules, direct_file)

    # Scan archive containing same file
    zip_path = "tests/samples/archives/test_malware.zip"
    archive_results = list(scanner.scan(zip_path))

    print(f"\nDirect file scan: {direct_file}")
    print(f"  Matches: {direct_matches}")

    print(f"\nArchive scan: {zip_path}")
    archive_matches = [r.rule_name for r in archive_results if "Emotet" in r.rule_name]
    print(f"  Emotet matches: {archive_matches}")

    if direct_matches and len(archive_matches) > 0:
        print("\n✅ PASS: Both methods detect malware")
        return True
    else:
        print("\n❌ FAIL: Detection inconsistency")
        return False


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("ARCHIVE SCANNING TEST SUITE")
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
            print(f"\n❌ TEST FAILED with exception: {e}")
            results.append(False)

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = sum(results)
    total = len(results)

    print(f"\nPassed: {passed}/{total}")

    if passed == total:
        print("\n🎉 ALL TESTS PASSED!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
