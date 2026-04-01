from __future__ import annotations

import pytest

from malware_scanner.archive.scanner import ArchiveScanner
from malware_scanner.exceptions import ArchiveBombError


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
