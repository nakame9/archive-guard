"""Đọc nội dung file nén hoàn toàn trong bộ nhớ.

Không bao giờ giải nén ra đĩa, nên tên file độc hại kiểu "../../evil.exe" không thể
ghi đè gì cả. Mỗi file con bị giới hạn kích thước để chống zip bomb.
"""
from __future__ import annotations

import bz2
import contextlib
import gzip
import io
import lzma
import os
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass

MAGIC = [
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
]
ARCHIVE_KINDS = {"zip", "rar", "7z", "tar", "gzip", "bzip2", "xz"}

TOO_BIG = "lớn hơn giới hạn, bỏ qua nội dung"
LOCKED = "được đặt mật khẩu, không đọc được nội dung"


@dataclass
class Member:
    name: str
    data: bytes | None = None  # None = không đọc được (mã hóa, quá lớn, thiếu công cụ…)
    size: int = 0  # kích thước khai báo khi chưa nén
    packed: int | None = None  # kích thước nén, nếu định dạng cho biết
    encrypted: bool = False
    note: str = ""
    link: str = ""  # đích của symlink/hardlink (tar)


class ArchiveError(Exception):
    """Không đọc được file nén (hỏng, cố tình làm hỏng, thiếu thư viện…)."""


class EncryptedArchive(ArchiveError):
    """Cả danh sách file cũng bị mã hóa – không xem được gì nếu thiếu mật khẩu."""


def archive_kind(head: bytes) -> str | None:
    for magic, kind in MAGIC:
        if head.startswith(magic):
            return kind
    if head[257:262] == b"ustar":
        return "tar"
    return None


def iter_members(kind, src, name, limit, passwords=()):
    """Duyệt các file bên trong một file nén.

    src: bytes (file nén nằm trong file nén khác) hoặc đường dẫn (file gốc trên đĩa).
    """
    reader = {"zip": _zip, "7z": _7z, "rar": _rar}.get(kind, _tar)
    try:
        yield from reader(src, name, kind, limit, list(passwords))
    except ArchiveError:
        raise
    except Exception as e:  # thư viện giải nén ném đủ loại lỗi với file hỏng/cố tình làm hỏng
        raise ArchiveError(f"{type(e).__name__}: {e}") from e


def _open(src):
    return io.BytesIO(src) if isinstance(src, bytes) else open(src, "rb")


def _read(fh, limit):
    data = fh.read(limit + 1)
    if len(data) > limit:
        return None, TOO_BIG
    return data, ""


def _read_member(open_fn, encrypted, passwords, limit):
    """Đọc một file con, thử lần lượt các mật khẩu nếu file bị mã hóa."""
    for pwd in passwords if encrypted else [None]:
        try:
            with open_fn(pwd) as fh:
                return _read(fh, limit)
        except Exception:
            if not encrypted:
                raise
    return None, LOCKED


def _zip(src, name, kind, limit, passwords):
    with _open(src) as f, zipfile.ZipFile(f) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            m = Member(info.filename, size=info.file_size, packed=info.compress_size,
                       encrypted=bool(info.flag_bits & 1))
            if info.file_size > limit:
                m.note = TOO_BIG
            else:
                try:
                    m.data, m.note = _read_member(
                        lambda pwd: zf.open(info, pwd=pwd.encode() if pwd else None),
                        m.encrypted, passwords, limit)
                except Exception as e:  # một file con hỏng không được làm dừng cả file nén
                    m.note = f"lỗi đọc: {e}"
            yield m


def _tar(src, name, kind, limit, passwords):
    with _open(src) as f:
        try:
            tf = tarfile.open(fileobj=f, mode="r:*")
        except tarfile.ReadError:
            if kind == "tar":
                raise
            tf = None
        if tf is None:  # .gz/.bz2/.xz chứa một file đơn, không phải .tar.gz
            f.seek(0)
            opener = {"gzip": gzip.open, "bzip2": bz2.open, "xz": lzma.open}[kind]
            with opener(f) as fh:
                data, note = _read(fh, limit)
            inner = os.path.splitext(os.path.basename(name))[0] or "data"
            yield Member(inner, data, len(data or b""), note=note)
            return
        with tf:
            for ti in tf:
                if ti.isdir():
                    continue
                m = Member(ti.name, size=ti.size, link=ti.linkname if ti.issym() or ti.islnk() else "")
                if ti.isfile():
                    if ti.size > limit:
                        m.note = TOO_BIG
                    else:
                        m.data, m.note = _read(tf.extractfile(ti), limit)
                yield m


def _7z(src, name, kind, limit, passwords):
    import py7zr

    locked = None
    for pwd in [None, *passwords]:
        try:
            members = _7z_read(py7zr, src, limit, pwd)
        except Exception as e:
            if pwd is None and not isinstance(e, py7zr.exceptions.PasswordRequired):
                raise
            continue  # sai mật khẩu → thử mật khẩu tiếp theo
        if any(m.encrypted and m.data is None for m in members):
            locked = locked or members
            continue
        yield from members
        return
    if locked is None:
        raise EncryptedArchive("7z bị mã hóa cả danh sách file" + (", sai mật khẩu" if passwords else ""))
    yield from locked


def _7z_read(py7zr, src, limit, pwd):
    from py7zr.io import BytesIOFactory

    with _open(src) as f, py7zr.SevenZipFile(f, password=pwd) as z:
        infos = [i for i in z.list() if not i.is_directory]
        encrypted = z.needs_password()
        locked = encrypted and pwd is None
        factory = BytesIOFactory(limit + 1)
        wanted = [i.filename for i in infos if i.uncompressed <= limit]
        if wanted and not locked:
            z.extract(targets=wanted, factory=factory)
    members = []
    for i in infos:
        m = Member(i.filename, size=i.uncompressed, packed=i.compressed, encrypted=encrypted)
        if locked:
            m.note = LOCKED
        elif i.filename not in factory.products:
            m.note = TOO_BIG
        else:
            buf = factory.get(i.filename)
            buf.seek(0)
            m.data, m.note = _read(buf, limit)
        members.append(m)
    return members


@contextlib.contextmanager
def _as_path(src, suffix):
    """rarfile gọi chương trình unrar bên ngoài nên cần một file thật trên đĩa."""
    if not isinstance(src, bytes):
        yield src
        return
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(src)
        yield path
    finally:
        os.unlink(path)


def _rar(src, name, kind, limit, passwords):
    import rarfile

    with _as_path(src, ".rar") as path:
        try:
            rf = rarfile.RarFile(path)
        except rarfile.PasswordRequired as e:
            # shortcut: chưa thử mật khẩu cho RAR mã hóa cả tên file (rar -hp); thêm khi có người cần
            raise EncryptedArchive("RAR bị mã hóa cả danh sách file") from e
        with rf:
            if rf.needs_password() and not rf.infolist():
                raise EncryptedArchive("RAR bị mã hóa cả danh sách file")
            for info in rf.infolist():
                if info.is_dir():
                    continue
                m = Member(info.filename, size=info.file_size, packed=info.compress_size,
                           encrypted=info.needs_password())
                if info.file_size > limit:
                    m.note = TOO_BIG
                else:
                    try:
                        m.data, m.note = _read_member(
                            lambda pwd: rf.open(info, pwd=pwd), m.encrypted, passwords, limit)
                    except rarfile.RarCannotExec:
                        m.note = "cần cài unrar hoặc 7-Zip để đọc nội dung RAR"
                    except Exception as e:
                        m.note = f"lỗi đọc: {e}"
                yield m
