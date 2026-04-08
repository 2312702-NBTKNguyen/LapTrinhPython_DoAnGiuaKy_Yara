from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, cast

import malware_scanner.service as service_module


@dataclass
class _DummyConn:
    closed: bool = False

    def close(self) -> None:
        self.closed = True


class _ArchiveScannerStub:
    def __init__(self, _rules: object):
        self.supported = False
        self.results = []

    def is_supported(self, _filepath: str) -> bool:
        return self.supported

    def scan(self, _filepath: str):
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
    monkeypatch.setattr(service_module, "create_malware_signature", lambda *args, **kwargs: None)
    return service_module.MalwareScanner(), conn


def test_scan_flow_archive_detection_short_circuits_hash_and_file_yara(monkeypatch) -> None:
    scanner, _ = _build_scanner(monkeypatch)
    monkeypatch.setattr(service_module, "calculate_file_hashes", lambda _path: _default_hashes())
    monkeypatch.setattr(service_module, "check_hash_in_db", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(service_module, "scan_with_yara", lambda *_args, **_kwargs: None)

    archive_scanner = cast(Any, scanner.archive_scanner)
    archive_scanner.supported = True
    archive_scanner.results = [SimpleNamespace(rule_name="RuleArchive")]

    scanner.scan_target("payload.zip")

    assert scanner.stats[service_module.SERVICE_STAT_SCANNED] == 1
    assert scanner.stats[service_module.SERVICE_STAT_YARA_MATCH] == 1
    assert scanner.stats[service_module.SERVICE_STAT_HASH_MATCH] == 0
    assert set(scanner.last_stage_timings) == {
        service_module.SERVICE_STAGE_HASH_CALCULATION,
        service_module.SERVICE_STAGE_ARCHIVE_SCAN,
    }


def test_scan_flow_uses_hash_stage_when_archive_has_no_detection(monkeypatch) -> None:
    scanner, _ = _build_scanner(monkeypatch)
    monkeypatch.setattr(service_module, "calculate_file_hashes", lambda _path: _default_hashes())
    monkeypatch.setattr(service_module, "check_hash_in_db", lambda *_args, **_kwargs: "KnownFamily")
    monkeypatch.setattr(service_module, "scan_with_yara", lambda *_args, **_kwargs: None)

    scanner.scan_target("payload.bin")

    assert scanner.stats[service_module.SERVICE_STAT_HASH_MATCH] == 1
    assert scanner.stats[service_module.SERVICE_STAT_YARA_MATCH] == 0


def test_scan_flow_marks_clean_when_archive_hash_and_yara_all_miss(monkeypatch) -> None:
    scanner, _ = _build_scanner(monkeypatch)
    monkeypatch.setattr(service_module, "calculate_file_hashes", lambda _path: _default_hashes())
    monkeypatch.setattr(service_module, "check_hash_in_db", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(service_module, "scan_with_yara", lambda *_args, **_kwargs: None)

    scanner.scan_target("clean.txt")

    assert scanner.stats[service_module.SERVICE_STAT_CLEAN] == 1
    assert scanner.stats[service_module.SERVICE_STAT_ERRORS] == 0


def test_scan_flow_counts_error_when_hash_calculation_fails(monkeypatch) -> None:
    scanner, _ = _build_scanner(monkeypatch)
    monkeypatch.setattr(service_module, "calculate_file_hashes", lambda _path: None)

    scanner.scan_target("broken.bin")

    assert scanner.stats[service_module.SERVICE_STAT_SCANNED] == 1
    assert scanner.stats[service_module.SERVICE_STAT_ERRORS] == 1


def test_scan_flow_close_releases_db_connection(monkeypatch) -> None:
    scanner, conn = _build_scanner(monkeypatch)

    scanner.close()

    assert conn.closed is True
