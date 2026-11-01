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


# --- RAR: file mẫu thật trong tests/data (tạo RAR cần chương trình `rar` có bản quyền) ---
DATA = __import__("pathlib").Path(__file__).parent / "data"


@pytest.fixture
def unrar():
    """Cần unrar/7-Zip/unar. CI Ubuntu cài unrar nên ở đó test KHÔNG được phép bị bỏ qua.

    bsdtar (có sẵn trên macOS) không tính: rarfile dùng được nó nhưng không đọc nổi RAR5 solid/có mật khẩu
    (kết quả là CHƯA QUÉT ĐỦ – an toàn, nhưng không kiểm tra được việc đọc nội dung).
    """
    import os
    import shutil
    import sys

    pytest.importorskip("rarfile")
    if not any(shutil.which(t) for t in ("unrar", "7z", "7zz", "unar")):
        if os.environ.get("GITHUB_ACTIONS") and sys.platform.startswith("linux"):
            pytest.fail("CI Ubuntu phải có unrar để test RAR chạy thật")
        pytest.skip("không có unrar/7-Zip/unar")


def _rar(name, *passwords):
    from archive_guard.scanner import Scanner
    return Scanner(use_clamav=False, passwords=passwords).scan_path(DATA / name)


def test_rar_contents_are_read(unrar):
    report = _rar("rar5-solid.rar")
    inner = [f for f in report.files if " > " in f.path]
    assert [f.path.split(" > ")[1] for f in inner] == ["stest1.txt", "stest2.txt"]
    assert all(f.kind == "text" and f.size == 2048 and not f.note for f in inner)
    assert report.verdict == "clean" and not report.incomplete


@pytest.mark.parametrize("passwords, verdict", [((), "incomplete"), (("sai",), "incomplete"),
                                                (("sai", "password"), "clean")])
def test_rar_with_password(unrar, passwords, verdict):
    report = _rar("rar5-psw.rar", *passwords)
    assert report.verdict == verdict
    assert bool(report.incomplete) == (verdict == "incomplete")  # có mật khẩu mà không mở được → không bao giờ SẠCH


def test_rar_in_sandboxed_worker(unrar, tmp_path):
    """unrar chạy BÊN TRONG worker đã áp sandbox (Landlock/seccomp): vẫn phải đọc được nội dung."""
    import json

    from archive_guard.cli import main
    out = tmp_path / "r.json"
    code = main([str(DATA / "rar5-psw.rar"), "-p", "password", "--no-clamav", "--json", str(out)])
    report = json.loads(out.read_text(encoding="utf-8"))["reports"][0]
    assert code == 0 and report["verdict"] == "clean" and report["complete"]
    assert len(report["files"]) == 3
