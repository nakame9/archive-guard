"""Chống archive bomb: ngân sách chung, streaming, giới hạn entry, timeout của engine.

Kiểm thử đối kháng bằng giới hạn nhỏ + dữ liệu vô hại, không tạo file bomb thật."""
import gzip
import io
import itertools
import os

import pytest
from helpers import make_7z, make_zip, rules_of, scan, scanned_count, tar_gz

from archive_guard.scanner import Scanner


def test_zip_bomb_ratio():
    report = scan(make_zip({"big.bin": bytes(60 << 20)}))
    assert "ARCHIVE.BOMB_RATIO" in rules_of(report)


def test_total_size_limit():
    report = scan(make_zip({"a.bin": bytes(700_000), "b.bin": bytes(700_000)}), max_total_mb=1)
    assert "ARCHIVE.BOMB_TOTAL" in rules_of(report)
    assert report.incomplete


def test_nesting_depth_limit():
    data = make_zip({"x.txt": b"x"})
    for i in range(4):
        data = make_zip({f"level{i}.zip": data})
    report = scan(data, max_depth=2)
    assert "ARCHIVE.TOO_DEEP" in rules_of(report)


def test_byte_budget_is_shared_across_nested_levels():
    # mỗi tầng chỉ 600 KB (dưới ngưỡng 1 MB) nhưng cộng các tầng lại thì vượt
    inner = [make_zip({f"part{i}.bin": os.urandom(300_000)}) for i in range(8)]
    report = scan(make_zip({f"level/{i}.zip": z for i, z in enumerate(inner)}), max_total_mb=1)
    assert "ARCHIVE.BOMB_TOTAL" in rules_of(report)
    assert scanned_count(report) < 1 + 8 * 2  # dừng sớm, không đọc hết
    assert sum(x.rule == "ARCHIVE.BOMB_TOTAL" for f in report.files for x in f.findings) == 1


def test_file_budget_is_shared_across_nested_levels():
    inner = make_zip({f"f{i}.txt": b"x" for i in range(40)})
    report = scan(make_zip({f"{i}.zip": inner for i in range(10)}), max_files=100)
    assert "ARCHIVE.TOO_MANY_FILES" in rules_of(report)
    assert len(report.files) <= 102


@pytest.mark.parametrize("kind, make", [
    ("zip", lambda d: make_zip({"a.bin": d})),
    ("tar", lambda d: tar_gz({"a.bin": d})),
    ("gzip", lambda d: gzip.compress(d)),
    ("7z", lambda d: make_7z({"a.bin": d})),
])
def test_budget_stops_in_the_middle_of_a_member(kind, make):
    from archive_guard.extract import CHUNK, Budget, BudgetExceeded, iter_members
    budget = Budget(max_bytes=1 << 20)
    with pytest.raises(BudgetExceeded) as e:
        list(iter_members(kind, make(os.urandom(6 << 20)), "a", limit=64 << 20, budget=budget))
    assert e.value.kind == "bytes"
    # dừng ngay sau khúc vượt ngưỡng, không đọc hết 6 MB của file con
    assert budget.bytes <= (1 << 20) + CHUNK, budget.bytes


def test_read_is_bounded_by_limit_not_by_declared_size():
    from archive_guard.extract import Budget, _read
    budget = Budget()
    data, note = _read(io.BytesIO(os.urandom(3 << 20)), 1 << 20, budget)  # "header khai" gì cũng mặc
    assert data is None and note and budget.bytes == (1 << 20) + 1


@pytest.mark.parametrize("make", [
    lambda: make_zip({**{f"d{i}/": b"" for i in range(100)}, "a.txt": b"hi"}),
    lambda: tar_gz({**{f"d{i}": None for i in range(100)}, "a.txt": b"hi"}),
])
def test_directories_count_as_entries(make):
    report = scan(make(), max_files=10)
    assert "ARCHIVE.TOO_MANY_FILES" in rules_of(report) and report.verdict != "clean"


def test_zip_entry_limit_applies_before_metadata_is_loaded(monkeypatch):
    import zipfile as zf_module
    data = make_zip({f"{i}.txt": b"x" for i in range(5000)})
    opened = []
    real = zf_module.ZipFile
    monkeypatch.setattr(zf_module, "ZipFile", lambda *a, **kw: opened.append(1) or real(*a, **kw))
    report = scan(data, max_files=10)
    assert "ARCHIVE.TOO_MANY_FILES" in rules_of(report)
    assert opened == [], "zipfile không được phép nạp danh mục 5000 entry"


def test_zip_oversized_directory_is_refused_before_loading():
    long_names = make_zip({("x" * 8000) + str(i): b"" for i in range(15)})  # danh mục ~120 KB cho 15 entry
    report = scan(long_names, max_files=20)
    assert "ARCHIVE.TOO_MANY_FILES" in rules_of(report)
    assert any("danh mục file" in x.detail for f in report.files for x in f.findings)


def test_zip64_directory_count_is_read():
    from archive_guard.extract import _zip_directory
    data = make_zip({f"{i}": b"" for i in range(70000)})  # > 65535 entry → bắt buộc dùng bản ghi ZIP64
    assert _zip_directory(io.BytesIO(data))[0] == 70000


def test_7z_extracts_in_batches_within_budget(monkeypatch):
    py7zr = pytest.importorskip("py7zr")
    calls = []
    real = py7zr.SevenZipFile.extract

    def spy(self, *a, targets=None, **kw):
        calls.append(len(targets or []))
        return real(self, *a, targets=targets, **kw)

    monkeypatch.setattr(py7zr.SevenZipFile, "extract", spy)
    data = make_7z({f"{i}.bin": os.urandom(400_000) for i in range(6)})
    full = scan(data, "a.7z", max_file_mb=1)
    assert scanned_count(full) == 7 and not full.incomplete
    assert max(calls[1:]) <= 2  # lần đầu dò mật khẩu; sau đó mỗi lô <= 1 MB (2 file) trong RAM
    calls.clear()
    limited = scan(data, "a.7z", max_file_mb=1, max_total_mb=1)
    assert "ARCHIVE.BOMB_TOTAL" in rules_of(limited)
    assert sum(calls[1:]) <= 3  # không giải nén các lô sau khi đã hết ngân sách


def test_time_budget(monkeypatch):
    from archive_guard import scanner as sc
    monkeypatch.setattr(sc.time, "monotonic", lambda: 1000.0)  # đồng hồ thô (Windows + Python 3.10) không nhích
    report = scan(make_zip({f"{i}.zip": make_zip({"a.txt": b"a"}) for i in range(5)}), timeout=0)
    assert "ARCHIVE.TIMEOUT" in rules_of(report)
    assert report.incomplete


def test_engines_never_exceed_scan_timeout(monkeypatch, tmp_path):
    from archive_guard import engines
    from archive_guard import scanner as sc
    seen = {}
    monkeypatch.setattr(engines, "find_clamav", lambda: "clamscan")
    monkeypatch.setattr(engines, "clamav_scan", lambda path, timeout: seen.setdefault("clamav", timeout) and [])
    monkeypatch.setattr(engines, "yara_scan", lambda c, d, timeout: seen.setdefault("yara", timeout) and [])
    p = tmp_path / "a.zip"
    p.write_bytes(make_zip({"a.txt": b"hi"}))
    Scanner(timeout=5).scan_path(p)
    assert 0 < seen["clamav"] <= 5 and 1 <= seen["yara"] <= 5
    scanner = Scanner(timeout=5)
    clock = itertools.chain([0.0], itertools.repeat(1e9))  # lần đầu đặt mốc; sau đó: đã hết giờ
    monkeypatch.setattr(sc.time, "monotonic", lambda: next(clock))
    seen.clear()
    report = scanner.scan_path(p)
    assert "clamav" not in seen
    assert report.verdict != "clean" and any("ClamAV" in x for x in report.incomplete)


def test_clamav_timeout_does_not_fall_back(monkeypatch):
    import subprocess

    from archive_guard import engines
    calls = []

    def slow(cmd, **kw):
        calls.append(kw["timeout"])
        raise subprocess.TimeoutExpired(cmd, kw["timeout"])

    monkeypatch.setattr(engines.shutil, "which", lambda name: name)
    monkeypatch.setattr(engines.subprocess, "run", slow)
    assert engines.clamav_scan("x.zip", timeout=3) is None
    assert len(calls) == 1 and calls[0] <= 3  # không thử tiếp clamscan sau khi clamdscan hết giờ
