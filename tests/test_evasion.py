"""Evasion corpus (tests/evasion.py): mỗi mẫu cho đúng kết luận mong đợi và đúng trạng thái độ phủ cấu trúc."""
import hashlib
import shutil
import subprocess

import pytest
from evasion import CORPUS
from helpers import make_pe, make_zip

from archive_guard.extract import zip_coverage
from archive_guard.scanner import Scanner


@pytest.fixture(scope="module")
def scanner():
    return Scanner(use_clamav=False)


def test_zip_metadata_fields():
    import io
    import struct
    import zipfile

    from helpers import EICAR, make_zip

    from archive_guard.extract import zip_metadata

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        zi = zipfile.ZipInfo("a.txt")
        zi.comment = EICAR
        zi.extra = struct.pack("<HH", 0x5455, 13) + b"x" * 13
        z.writestr(zi, b"a")
    assert zip_metadata(buf.getvalue()) == [("comment của a.txt", EICAR)]
    assert zip_metadata(make_zip({"a.txt": b"a"})) == []


@pytest.mark.parametrize("name", CORPUS)
def test_evasion_sample(tmp_path, scanner, name):
    build, verdict, unexplained, note = CORPUS[name]
    path = tmp_path / f"{name}.zip"
    path.write_bytes(build())
    report = scanner.scan_path(path).to_dict()
    coverage = report["files"][0]["coverage"]
    assert "error" not in coverage
    assert report["verdict"] == verdict
    assert (coverage["unexplained_bytes"] > 0) == unexplained
    assert coverage["explained"] + coverage["unexplained_bytes"] == coverage["bytes"] == path.stat().st_size
    if note in ("HIDDEN_UNSCANNED", "UNEXPLAINED_BYTES"):
        assert note in {r["code"] for r in report["incomplete_reasons"]}


def test_zip_inside_pe_section_is_fully_explained():
    data = make_pe([(".rsrc", make_zip({"a.txt": b"a"}) + bytes(64), 0x40000040)])
    assert zip_coverage(data, outer="pe")["unexplained_bytes"] == 0
    assert zip_coverage(data + b"JUNK" * 16, outer="pe")["unexplained_bytes"] == 64


def test_zip_inside_ole_container_is_explained():
    data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(504) + make_zip({"a.txt": b"a"}) + bytes(512)
    coverage = zip_coverage(data, outer="ole")
    assert coverage["unexplained_bytes"] == 0
    assert coverage["container"] == "ole"
    assert zip_coverage(data, outer="unknown")["unexplained_bytes"] == 1024
    # định dạng khác chưa được xác nhận là container: byte ngoài ZIP vẫn là byte lạ (vd. "%PDF-" + ZIP + rác)
    assert zip_coverage(data, outer="pdf")["unexplained_bytes"] == 1024


def test_benign_zips_are_fully_explained(tmp_path, scanner):
    # đối chứng: ZIP sạch do zipfile tạo (deflate, stored, comment, data descriptor khi ghi luồng, ZIP64) phủ 100%
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", b"a" * 1000)
        z.writestr(zipfile.ZipInfo("b.bin"), bytes(range(256)) * 10, zipfile.ZIP_DEFLATED)
        with z.open("luong.txt", "w", force_zip64=True) as f:  # ghi luồng: data descriptor + extra ZIP64
            f.write(b"x" * 5000)
        z.comment = b"ghi chu"
    unseekable = io.BytesIO()  # file không seek được → zipfile buộc phải dùng data descriptor có chữ ký

    class NoSeek(io.RawIOBase):
        def writable(self):
            return True

        def write(self, b):
            return unseekable.write(b)
    with zipfile.ZipFile(NoSeek(), "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("c.txt", b"c" * 3000)
    for i, data in enumerate((buf.getvalue(), unseekable.getvalue())):
        path = tmp_path / f"sach{i}.zip"
        path.write_bytes(data)
        report = scanner.scan_path(path).to_dict()
        assert report["verdict"] == "clean"
        assert report["files"][0]["coverage"]["unexplained_bytes"] == 0, report["files"][0]["coverage"]


SEVEN_ZIP = shutil.which("7zz") or shutil.which("7z")


def _seven_zip_members(path):
    """{tên: {sha256 nội dung}} mà 7-Zip giải nén ra (1 tầng). None nếu 7-Zip từ chối file.

    Tên trùng: `7z e -so <tên>` nối nội dung MỌI entry cùng tên theo thứ tự danh sách → cắt lại theo `Size` từng entry.
    """
    listing = subprocess.run([SEVEN_ZIP, "l", "-slt", "-ba", str(path)], capture_output=True, timeout=60)
    if listing.returncode:
        return None
    entries, name = [], None  # [(tên, kích thước)] theo thứ tự 7-Zip liệt kê
    for line in listing.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith("Path = "):
            name = line[7:]
        elif line.startswith("Size = ") and name is not None:
            entries.append((name, int(line[7:] or 0)))
            name = None
    out = {}
    for n in dict.fromkeys(n for n, _ in entries):
        data = subprocess.run([SEVEN_ZIP, "e", "-so", "-y", str(path), n], capture_output=True, timeout=60).stdout
        pos = 0
        for size in (s for m, s in entries if m == n):
            out.setdefault(n, set()).add(hashlib.sha256(data[pos:pos + size]).hexdigest())
            pos += size
    return out


@pytest.mark.skipif(SEVEN_ZIP is None, reason="cần 7-Zip (7zz/7z) – CI cài trong job differential")
@pytest.mark.parametrize("name", CORPUS)
def test_everything_7zip_extracts_was_inspected(tmp_path, scanner, name):
    """Điều thật sự cần: mọi thứ 7-Zip lấy ra được (tên + nội dung) đều đã qua trình quét, hoặc báo CHƯA QUÉT ĐỦ."""
    build, _, _, _ = CORPUS[name]
    path = tmp_path / f"{name}.zip"
    path.write_bytes(build())
    seen = _seven_zip_members(path)
    if not seen:
        pytest.skip("7-Zip không mở được mẫu này")
    report = scanner.scan_path(path).to_dict()
    if not report["complete"] or report["verdict"] == "malicious":
        return  # đã báo chưa quét đủ, hoặc đã chặn
    ours = {f["sha256"] for f in report["files"][1:]}
    missed = {n: h - ours for n, h in seen.items() if h - ours and h != {hashlib.sha256(b"").hexdigest()}}
    assert not missed, f"7-Zip lấy ra nội dung mà ArchiveGuard không quét: {sorted(missed)}"
