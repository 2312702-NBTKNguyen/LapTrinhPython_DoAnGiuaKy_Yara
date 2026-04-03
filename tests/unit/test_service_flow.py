from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import malware_scanner.service as service_module
from malware_scanner.exceptions import ArchiveError, UnsupportedFormatError


@dataclass
class _DummyConn:
    closed: bool = False

    def close(self) -> None:
        self.closed = True


class _ArchiveScannerStub:
    def __init__(self, _rules: object):
        self.supported = False
        self.results = []
        self.error: ArchiveError | None = None

    def is_supported(self, _filepath: str) -> bool:
        return self.supported

    def scan(self, _filepath: str):
        if self.error is not None:
            raise self.error
        for result in self.results:
            yield result


def _default_hashes() -> dict[str, str]:
    return {
        "md5_hash": "m",
        "sha1_hash": "s1",
        "sha256_hash": "s256",
        "sha3_384_hash": "s3384",
    }


def _build_scanner(monkeypatch):
    conn = _DummyConn()
    monkeypatch.setattr(service_module, "connect_db", lambda: conn)
    monkeypatch.setattr(service_module, "load_yara_rules", lambda _path: object())
    monkeypatch.setattr(service_module, "ArchiveScanner", _ArchiveScannerStub)
    monkeypatch.setattr(service_module, "log_scan_result", lambda *args, **kwargs: None)
    monkeypatch.setattr(service_module, "insert_malware_variant", lambda *args, **kwargs: None)
    return service_module.MalwareScanner(), conn


def test_scan_target_increments_error_when_hash_calculation_fails(monkeypatch) -> None:
    scanner, _ = _build_scanner(monkeypatch)
    monkeypatch.setattr(service_module, "calculate_file_hashes", lambda _path: None)

    scanner.scan_target("sample.bin")

    assert scanner.stats["scanned"] == 1
    assert scanner.stats["errors"] == 1


def test_scan_target_short_circuits_on_archive_match(monkeypatch) -> None:
    scanner, _ = _build_scanner(monkeypatch)
    monkeypatch.setattr(service_module, "calculate_file_hashes", lambda _path: _default_hashes())
    monkeypatch.setattr(service_module, "check_hash_in_db", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(service_module, "scan_with_yara", lambda *_args, **_kwargs: None)

    scanner.archive_scanner.supported = True
    scanner.archive_scanner.results = [SimpleNamespace(rule_name="RuleA")]

    scanner.scan_target("payload.zip")

    assert scanner.stats["yara_match"] == 1
    assert scanner.stats["hash_match"] == 0
    assert scanner.stats["clean"] == 0


def test_scan_target_falls_back_to_hash_when_archive_unsupported(monkeypatch) -> None:
    scanner, _ = _build_scanner(monkeypatch)
    monkeypatch.setattr(service_module, "calculate_file_hashes", lambda _path: _default_hashes())
    monkeypatch.setattr(service_module, "check_hash_in_db", lambda *_args, **_kwargs: "KnownFamily")

    scanner.archive_scanner.supported = True
    scanner.archive_scanner.error = UnsupportedFormatError("skip")

    scanner.scan_target("payload.zip")

    assert scanner.stats["archive_skipped"] == 1
    assert scanner.stats["hash_match"] == 1


def test_scan_target_marks_error_when_yara_scan_fails(monkeypatch) -> None:
    scanner, _ = _build_scanner(monkeypatch)
    monkeypatch.setattr(service_module, "calculate_file_hashes", lambda _path: _default_hashes())
    monkeypatch.setattr(service_module, "check_hash_in_db", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(service_module, "scan_with_yara", lambda *_args, **_kwargs: "__SCAN_ERROR__")

    scanner.scan_target("payload.bin")

    assert scanner.stats["errors"] == 1
    assert scanner.stats["clean"] == 0


def test_scan_target_marks_clean_when_no_detection(monkeypatch) -> None:
    scanner, _ = _build_scanner(monkeypatch)
    monkeypatch.setattr(service_module, "calculate_file_hashes", lambda _path: _default_hashes())
    monkeypatch.setattr(service_module, "check_hash_in_db", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(service_module, "scan_with_yara", lambda *_args, **_kwargs: None)

    scanner.scan_target("payload.txt")

    assert scanner.stats["clean"] == 1
    assert scanner.stats["errors"] == 0


def test_scanner_close_closes_database_connection(monkeypatch) -> None:
    scanner, conn = _build_scanner(monkeypatch)

    scanner.close()

    assert conn.closed is True
