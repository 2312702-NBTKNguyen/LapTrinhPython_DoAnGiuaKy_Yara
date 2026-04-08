from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, cast

import malware_scanner.service as moduleDichVu


@dataclass
class _KetNoiDbGia:
    closed: bool = False

    def close(self) -> None:
        self.closed = True


class _MayQuetArchiveGia:
    def __init__(self, _rules: object):
        self.duocHoTro = False
        self.ketQua = []

    def hoTroDinhDang(self, _duongDanFile: str) -> bool:
        return self.duocHoTro

    def quet(self, _duongDanFile: str):
        for ketQua in self.ketQua:
            yield ketQua


def _hashMacDinh() -> dict[str, str]:
    return {
        "md5_hash": "m",
        "sha1_hash": "s1",
        "sha256_hash": "s256",
        "sha3_384_hash": "s3384",
    }


def _taoMayQuet(monkeypatch):
    ketNoi = _KetNoiDbGia()
    monkeypatch.setattr(moduleDichVu, "ketNoiDb", lambda: ketNoi)
    monkeypatch.setattr(moduleDichVu, "napYaraRules", lambda _duongDan: object())
    monkeypatch.setattr(moduleDichVu, "mayQuetArchive", _MayQuetArchiveGia)
    monkeypatch.setattr(moduleDichVu, "ghiNhanKetQuaQuet", lambda *args, **kwargs: None)
    monkeypatch.setattr(moduleDichVu, "taoMalwareSignature", lambda *args, **kwargs: None)
    return moduleDichVu.mayQuetMalware(), ketNoi


def testQuetArchivePhatHienBoQuaHashVaYaraFile(monkeypatch) -> None:
    mayQuet, _ = _taoMayQuet(monkeypatch)
    monkeypatch.setattr(moduleDichVu, "tinhHashFile", lambda _duongDan: _hashMacDinh())
    monkeypatch.setattr(moduleDichVu, "kiemTraHashTrongDb", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(moduleDichVu, "quetBangYara", lambda *_args, **_kwargs: None)

    mayQuetArchive = cast(Any, mayQuet.mayQuetArchive)
    mayQuetArchive.duocHoTro = True
    mayQuetArchive.ketQua = [SimpleNamespace(tenRule="RuleArchive")]

    mayQuet.quetMucTieu("payload.zip")

    assert mayQuet.thongKeQuet[moduleDichVu.thongKeDaQuet] == 1
    assert mayQuet.thongKeQuet[moduleDichVu.thongKeYaraMatch] == 1
    assert mayQuet.thongKeQuet[moduleDichVu.thongKeHashMatch] == 0
    assert set(mayQuet.thoiGianGiaiDoanCuoi) == {
        moduleDichVu.giaiDoanTinhHash,
        moduleDichVu.giaiDoanQuetArchive,
    }


def testQuetSuDungGiaiDoanHashKhiArchiveKhongPhatHien(monkeypatch) -> None:
    mayQuet, _ = _taoMayQuet(monkeypatch)
    monkeypatch.setattr(moduleDichVu, "tinhHashFile", lambda _duongDan: _hashMacDinh())
    monkeypatch.setattr(moduleDichVu, "kiemTraHashTrongDb", lambda *_args, **_kwargs: "KnownFamily")
    monkeypatch.setattr(moduleDichVu, "quetBangYara", lambda *_args, **_kwargs: None)

    mayQuet.quetMucTieu("payload.bin")

    assert mayQuet.thongKeQuet[moduleDichVu.thongKeHashMatch] == 1
    assert mayQuet.thongKeQuet[moduleDichVu.thongKeYaraMatch] == 0


def testQuetDanhDauSachKhiArchiveHashYaraKhongKhop(monkeypatch) -> None:
    mayQuet, _ = _taoMayQuet(monkeypatch)
    monkeypatch.setattr(moduleDichVu, "tinhHashFile", lambda _duongDan: _hashMacDinh())
    monkeypatch.setattr(moduleDichVu, "kiemTraHashTrongDb", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(moduleDichVu, "quetBangYara", lambda *_args, **_kwargs: None)

    mayQuet.quetMucTieu("clean.txt")

    assert mayQuet.thongKeQuet[moduleDichVu.thongKeSach] == 1
    assert mayQuet.thongKeQuet[moduleDichVu.thongKeLoi] == 0


def testQuetDemLoiKhiTinhHashThatBai(monkeypatch) -> None:
    mayQuet, _ = _taoMayQuet(monkeypatch)
    monkeypatch.setattr(moduleDichVu, "tinhHashFile", lambda _duongDan: None)

    mayQuet.quetMucTieu("broken.bin")

    assert mayQuet.thongKeQuet[moduleDichVu.thongKeDaQuet] == 1
    assert mayQuet.thongKeQuet[moduleDichVu.thongKeLoi] == 1


def testDongKetNoiGiaiPhongKetNoiDb(monkeypatch) -> None:
    mayQuet, ketNoi = _taoMayQuet(monkeypatch)

    mayQuet.dongKetNoi()

    assert ketNoi.closed is True
