from __future__ import annotations

import os
import zipfile
from types import SimpleNamespace

import pytest

import malware_scanner.archive.rar as rar_module
import malware_scanner.archive.scanner as scanner_module
import malware_scanner.archive.zip as zip_module
from malware_scanner.archive.scanner import ArchiveScanner
from malware_scanner.exceptions import ArchiveBombError, ExtractionError, PasswordProtectedError, UnsupportedFormatError


class _DummyRules:
    pass


@pytest.fixture
def scanner() -> ArchiveScanner:
    return ArchiveScanner(_DummyRules(), max_size_mb=1, max_ratio=10, max_files=2)


def test_validate_member_raises_when_file_count_exceeds_limit(scanner: ArchiveScanner) -> None:
    with pytest.raises(ArchiveBombError):
        scanner._validate_archive_member(file_count=3, file_size=100, compressed_size=10)


def test_validate_member_raises_when_compression_ratio_exceeds_limit(scanner: ArchiveScanner) -> None:
    with pytest.raises(ArchiveBombError):
        scanner._validate_archive_member(file_count=1, file_size=1000, compressed_size=10)


def test_validate_member_returns_false_for_oversized_member(scanner: ArchiveScanner) -> None:
    oversized = scanner.max_size_bytes + 1
    assert scanner._validate_archive_member(file_count=1, file_size=oversized, compressed_size=oversized) is False


def test_validate_member_returns_true_for_safe_member(scanner: ArchiveScanner) -> None:
    assert scanner._validate_archive_member(file_count=1, file_size=4096, compressed_size=1024) is True


def _build_three_level_nested_zip(tmp_path) -> str:
    level2_path = tmp_path / "level2.zip"
    with zipfile.ZipFile(level2_path, "w", zipfile.ZIP_DEFLATED) as level2_zip:
        level2_zip.writestr("payload.txt", b"MALWARE_PAYLOAD")

    level1_path = tmp_path / "level1.zip"
    with zipfile.ZipFile(level1_path, "w", zipfile.ZIP_DEFLATED) as level1_zip:
        level1_zip.write(level2_path, arcname="level2.zip")

    outer_path = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer_path, "w", zipfile.ZIP_DEFLATED) as outer_zip:
        outer_zip.write(level1_path, arcname="level1.zip")

    return str(outer_path)


def _build_zip_with_safe_and_oversized_members(tmp_path) -> str:
    zip_path = tmp_path / "members.zip"
    safe_payload = b"MALWARE_SAFE_PAYLOAD"
    oversized_payload = b"MALWARE_OVERSIZED_PAYLOAD" + os.urandom(1_200_000)

    with zipfile.ZipFile(zip_path, "w") as zip_obj:
        zip_obj.writestr("safe.txt", safe_payload, compress_type=zipfile.ZIP_STORED)
        zip_obj.writestr("oversized.bin", oversized_payload, compress_type=zipfile.ZIP_STORED)

    return str(zip_path)


def test_nested_depth_off_by_one_in_real_scan_flow(tmp_path, monkeypatch) -> None:
    def _fake_scan_data_with_yara(_rules, data: bytes, filepath: str = ""):
        if b"MALWARE_PAYLOAD" in data:
            return "Rule_NestedDepth"
        return None

    monkeypatch.setattr(scanner_module, "scan_data_with_yara", _fake_scan_data_with_yara)
    archive_path = _build_three_level_nested_zip(tmp_path)

    scanner_depth_1 = ArchiveScanner(_DummyRules(), max_depth=1)
    results_depth_1 = list(scanner_depth_1.scan(archive_path))

    scanner_depth_2 = ArchiveScanner(_DummyRules(), max_depth=2)
    results_depth_2 = list(scanner_depth_2.scan(archive_path))

    assert results_depth_1 == []
    assert any(result.rule_name == "Rule_NestedDepth" for result in results_depth_2)


def test_oversized_member_is_skipped_in_real_scan_flow(tmp_path, monkeypatch) -> None:
    def _fake_scan_data_with_yara(_rules, data: bytes, filepath: str = ""):
        if b"MALWARE_" in data:
            return "Rule_SizeCheck"
        return None

    monkeypatch.setattr(scanner_module, "scan_data_with_yara", _fake_scan_data_with_yara)
    archive_path = _build_zip_with_safe_and_oversized_members(tmp_path)

    scanner = ArchiveScanner(_DummyRules(), max_size_mb=1, max_ratio=10_000)
    results = list(scanner.scan(archive_path))

    matched_paths = [result.file_path for result in results]
    assert any(path.endswith("::safe.txt") for path in matched_paths)
    assert not any(path.endswith("::oversized.bin") for path in matched_paths)


def test_scan_zip_raises_extraction_error_for_corrupted_zip(tmp_path) -> None:
    scanner = ArchiveScanner(_DummyRules())
    bad_zip = tmp_path / "broken.zip"
    bad_zip.write_bytes(b"not-a-valid-zip")

    with pytest.raises(ExtractionError):
        list(scanner.scan(str(bad_zip)))


def test_scan_zip_raises_password_protected_error(monkeypatch) -> None:
    encrypted_info = SimpleNamespace(
        flag_bits=0x1,
        is_dir=lambda: False,
        file_size=12,
        compress_size=6,
        filename="payload.bin",
    )

    class _FakeZipFile:
        def __init__(self, _filepath: str, _mode: str):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def infolist(self):
            return [encrypted_info]

    monkeypatch.setattr(zip_module.zipfile, "ZipFile", _FakeZipFile)

    scanner = ArchiveScanner(_DummyRules())
    with pytest.raises(PasswordProtectedError):
        list(zip_module.scan_zip(scanner, "sample.zip", depth=0))


def test_scan_rar_raises_unsupported_when_rarfile_missing(monkeypatch) -> None:
    def _raise_import_error(_name: str):
        raise ImportError("rarfile not installed")

    monkeypatch.setattr(rar_module.importlib, "import_module", _raise_import_error)

    scanner = ArchiveScanner(_DummyRules())
    with pytest.raises(UnsupportedFormatError):
        list(rar_module.scan_rar(scanner, "sample.rar", depth=0))


def test_scan_rar_raises_unsupported_when_no_backend_tool(monkeypatch) -> None:
    class _FakeRarFileContext:
        def __init__(self, _filepath: str, _mode: str):
            pass

        def __enter__(self):
            raise fake_module.RarCannotExec("tool not found")

        def __exit__(self, exc_type, exc, tb):
            return False

    fake_module = SimpleNamespace(
        RarFile=_FakeRarFileContext,
        PasswordRequired=type("PasswordRequired", (Exception,), {}),
        NotRarFile=type("NotRarFile", (Exception,), {}),
        BadRarFile=type("BadRarFile", (Exception,), {}),
        RarCannotExec=type("RarCannotExec", (Exception,), {}),
        Error=type("Error", (Exception,), {}),
    )

    monkeypatch.setattr(rar_module.importlib, "import_module", lambda _name: fake_module)
    monkeypatch.setattr(rar_module, "configure_rar_backend", lambda _scanner, _module: None)

    scanner = ArchiveScanner(_DummyRules())
    with pytest.raises(UnsupportedFormatError):
        list(rar_module.scan_rar(scanner, "sample.rar", depth=0))
