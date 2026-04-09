from __future__ import annotations

from dataclasses import dataclass

import malware_scanner.scan_runtime as runtime_module
from malware_scanner.scan_runtime import DetectionMethod


@dataclass
class _DummyConn:
    closed: bool = False

    def close(self) -> None:
        self.closed = True


class _RepositoryStub:
    def __init__(self):
        self.connection = _DummyConn()
        self.hash_match: str | None = None
        self.outcomes = []

    def find_signature_by_hash(self, _file_hash: str) -> str | None:
        return self.hash_match

    def save_outcome(self, outcome) -> None:
        self.outcomes.append(outcome)

    def fetch_scan_results(self, _start_time, detected_only: bool = False):
        _ = detected_only
        return []

    def close(self) -> None:
        self.connection.close()


def _default_hashes() -> dict[str, str]:
    return {
        "md5_hash": "m",
        "sha1_hash": "s1",
        "sha256_hash": "s256",
        "sha3_384_hash": "s3384",
    }


def _build_scanner(monkeypatch):
    repository = _RepositoryStub()
    monkeypatch.setattr(runtime_module, "ScanStore", lambda: repository)
    monkeypatch.setattr(runtime_module, "load_yara_rules", lambda _path: object())
    return runtime_module.ScannerEngine(), repository


def test_scan_flow_uses_hash_stage_when_db_has_no_match_then_runs_file_yara(monkeypatch) -> None:
    scanner, repository = _build_scanner(monkeypatch)
    monkeypatch.setattr(runtime_module, "calculate_file_hashes", lambda _path: _default_hashes())
    monkeypatch.setattr(runtime_module, "scan_with_yara", lambda *_args, **_kwargs: "RuleFile")

    outcome = scanner.scan_file("payload.bin")

    assert scanner.metrics["scanned"] == 1
    assert scanner.metrics["yara_match"] == 1
    assert scanner.metrics["hash_match"] == 0
    assert outcome is not None
    assert outcome.detection.method == DetectionMethod.YARA_MATCH
    assert repository.outcomes[-1].detection.signature == "RuleFile"
    assert set(scanner.stage_timings) == {
        "hash_calculation",
        "db_hash_lookup",
        "file_yara_scan",
    }


def test_scan_flow_uses_hash_stage_when_db_has_match(monkeypatch) -> None:
    scanner, repository = _build_scanner(monkeypatch)
    repository.hash_match = "KnownFamily"
    monkeypatch.setattr(runtime_module, "calculate_file_hashes", lambda _path: _default_hashes())
    monkeypatch.setattr(runtime_module, "scan_with_yara", lambda *_args, **_kwargs: None)

    outcome = scanner.scan_file("payload.bin")

    assert scanner.metrics["hash_match"] == 1
    assert scanner.metrics["yara_match"] == 0
    assert outcome is not None
    assert outcome.detection.method == DetectionMethod.HASH_MATCH


def test_scan_flow_marks_clean_when_hash_and_yara_all_miss(monkeypatch) -> None:
    scanner, repository = _build_scanner(monkeypatch)
    monkeypatch.setattr(runtime_module, "calculate_file_hashes", lambda _path: _default_hashes())
    monkeypatch.setattr(runtime_module, "scan_with_yara", lambda *_args, **_kwargs: None)

    outcome = scanner.scan_file("clean.txt")

    assert scanner.metrics["clean"] == 1
    assert scanner.metrics["errors"] == 0
    assert outcome is not None
    assert outcome.detection.method == DetectionMethod.CLEAN
    assert repository.outcomes[-1].detection.signature == "None"


def test_scan_flow_counts_error_when_hash_calculation_fails(monkeypatch) -> None:
    scanner, _ = _build_scanner(monkeypatch)
    monkeypatch.setattr(runtime_module, "calculate_file_hashes", lambda _path: None)

    outcome = scanner.scan_file("broken.bin")

    assert scanner.metrics["scanned"] == 1
    assert scanner.metrics["errors"] == 1
    assert outcome is None


def test_scan_flow_close_releases_repository_connection(monkeypatch) -> None:
    scanner, repository = _build_scanner(monkeypatch)

    scanner.close()

    assert repository.connection.closed is True
