"""Định dạng nén, mật khẩu, định dạng chưa hỗ trợ: phần chưa quét không bao giờ là SẠCH."""
import gzip
import io
import tarfile

import pytest
from helpers import (
    EICAR,
    FAKE_EXE,
    PS_DOWNLOADER,
    make_7z,
    make_zip,
    rules_of,
    scan,
    set_encrypted_flag,
)

from archive_guard.scanner import Scanner


def test_tar_gz_symlink_and_single_gz():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        info = tarfile.TarInfo("x/run.ps1")
        info.size = len(PS_DOWNLOADER)
        t.addfile(info, io.BytesIO(PS_DOWNLOADER))
        link = tarfile.TarInfo("x/passwd")
        link.type, link.linkname = tarfile.SYMTYPE, "../../../etc/passwd"
        t.addfile(link)
    assert {"DOWNLOAD.EXEC_PS", "NAME.PATH_TRAVERSAL"} <= rules_of(scan(buf.getvalue(), "a.tar.gz"))
    assert "DOWNLOAD.EXEC_PS" in rules_of(scan(gzip.compress(PS_DOWNLOADER), "run.ps1.gz"))


def test_7z_with_and_without_password():
    assert scan(make_7z({"eicar.com": EICAR}), "a.7z").verdict == "malicious"
    locked = make_7z({"eicar.com": EICAR}, password="infected")
    assert scan(locked, "a.7z").incomplete
    assert scan(locked, "a.7z", passwords=["sai", "infected"]).verdict == "malicious"
    hidden = make_7z({"eicar.com": EICAR}, password="infected", header_encryption=True)
    assert "ARCHIVE.ENCRYPTED" in rules_of(scan(hidden, "a.7z"))


def test_password_protected_executable():
    report = scan(set_encrypted_flag(make_zip({"invoice.exe": FAKE_EXE})))
    assert "ARCHIVE.ENCRYPTED_EXEC" in rules_of(report)
    assert report.incomplete


@pytest.mark.parametrize("name, data", [
    ("zip mật khẩu", lambda: set_encrypted_flag(make_zip({"hoadon.txt": b"x"}))),
    ("file nén hỏng", lambda: make_zip({"a.txt": b"x" * 100})[:60]),
    ("CAB chưa hỗ trợ", lambda: make_zip({"setup.cab": b"MSCF" + bytes(200)})),
    ("ISO chưa hỗ trợ", lambda: make_zip({"disk.bin": bytes(0x8001) + b"CD001" + bytes(100)})),
])
def test_unchecked_content_is_never_clean(name, data):
    report = scan(data())
    assert report.verdict == "incomplete", name
    assert report.incomplete


def test_engine_error_is_incomplete_not_clean_or_crash(monkeypatch):
    from archive_guard import engines

    def broken(*a):
        raise RuntimeError("yara timeout")

    monkeypatch.setattr(engines, "yara_scan", broken)
    report = scan(make_zip({"a.txt": b"hi"}))
    assert report.verdict == "incomplete"
    assert any("YARA lỗi" in x for x in report.incomplete)
    assert scan(make_zip({"invoice.pdf.exe": FAKE_EXE})).verdict == "suspicious"  # heuristic vẫn chạy


def test_root_archive_size_limit(tmp_path):
    path = tmp_path / "a.zip"
    path.write_bytes(make_zip({"a.txt": b"hi"}))
    report = Scanner(use_clamav=False, max_archive_mb=0).scan_path(path)
    assert report.verdict == "incomplete" and "max-archive-size" in report.incomplete[0]
