from __future__ import annotations

from malware_scanner.detection.scan_variants import iter_detection_variants


def test_iter_detection_variants_yields_raw_data_first() -> None:
    data = b"A" * 64

    variants = list(iter_detection_variants(data, filepath="payload.bin"))

    assert variants
    assert variants[0] == data


def test_iter_detection_variants_includes_null_stripped_variant() -> None:
    data = (b"A\x00" * 40)
    expected = data.replace(b"\x00", b"")

    variants = list(iter_detection_variants(data, filepath="payload.bin"))

    assert expected in variants
