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
import struct
import tarfile
import tempfile
import time
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


CHUNK = 1 << 20  # đọc/giải nén từng khúc 1 MB, cập nhật ngân sách sau mỗi khúc
ZIP_CD_BYTES_PER_ENTRY = 1024  # danh mục ZIP trung bình > 1 KB/entry là bất thường (tên dài + extra field)


class BudgetExceeded(BaseException):
    """Vượt ngân sách chung. kind = files | bytes | time.

    Kế thừa BaseException (như KeyboardInterrupt) để KHÔNG khối `except Exception` nào – của ta hay của thư
    viện giải nén – vô tình nuốt mất tín hiệu dừng.
    """

    def __init__(self, kind, detail=""):
        super().__init__(kind, detail)
        self.kind, self.detail = kind, detail


class Budget:
    """Ngân sách dùng chung cho MỌI tầng lồng nhau của một lần quét, kiểm tra ngay TRONG lúc giải nén."""

    def __init__(self, max_files=1 << 62, max_bytes=1 << 62, timeout=1e12):
        self.max_files, self.max_bytes = max_files, max_bytes
        self.files = self.bytes = 0
        self.deadline = time.monotonic() + timeout
        self.stopped = False

    def entry(self):
        """Gọi cho MỌI entry khi duyệt danh mục, kể cả thư mục."""
        self.files += 1
        if self.files > self.max_files:
            raise BudgetExceeded("files")
        self.check()

    def check_entries(self, n, detail=""):
        """Kiểm tra số entry khai báo TRƯỚC khi nạp metadata của chúng."""
        if self.files + n > self.max_files:
            raise BudgetExceeded("files", detail or f"danh mục khai báo {n} entry")

    def take(self, n):
        """Gọi sau MỖI khúc dữ liệu giải nén ra (hoặc với kích thước khai báo của phần bị bỏ qua)."""
        self.bytes += n
        self.check()

    def remaining(self):
        return self.max_bytes - self.bytes

    def check(self):
        if self.bytes > self.max_bytes:
            raise BudgetExceeded("bytes")
        if time.monotonic() >= self.deadline:  # >=: đồng hồ Windows/Python 3.10 nhích theo nấc ~16 ms
            raise BudgetExceeded("time")


class ArchiveError(Exception):
    """Không đọc được file nén (hỏng, cố tình làm hỏng, thiếu thư viện…)."""


class EncryptedArchive(ArchiveError):
    """Cả danh sách file cũng bị mã hóa – không xem được gì nếu thiếu mật khẩu."""


# Định dạng CHỨA file nhưng chưa mở được: nội dung bên trong không được kiểm tra đầy đủ
UNSUPPORTED = [
    (0, b"MSCF", "CAB"), (0, b"\x28\xb5\x2f\xfd", "Zstandard"), (0, b"MSWIM", "WIM"),
    (0, b"\x04\x22\x4d\x18", "LZ4"), (0, b"LZIP", "Lzip"), (0, b"\x60\xea", "ARJ"),
    (0, b"conectix", "VHD"), (0, b"vhdxfile", "VHDX"), (0, b"xar!", "XAR/PKG"),
    (0x8001, b"CD001", "ISO"), (0x8801, b"CD001", "ISO"), (0x9001, b"CD001", "ISO"),
    (2, b"-lh", "LZH"), (0, b"\xef\xbe\xad\xdeNullsoftInst", "NSIS"),
]


def unsupported_container(data: bytes) -> str | None:
    return next((name for off, magic, name in UNSUPPORTED if data[off:off + len(magic)] == magic), None)


def archive_kind(head: bytes) -> str | None:
    for magic, kind in MAGIC:
        if head.startswith(magic):
            return kind
    if head[257:262] == b"ustar":
        return "tar"
    return None


def iter_members(kind, src, name, limit, passwords=(), budget=None):
    """Duyệt các file bên trong một file nén.

    src: bytes (file nén nằm trong file nén khác) hoặc đường dẫn (file gốc trên đĩa).
    budget: ngân sách chung; mỗi entry và mỗi khúc dữ liệu giải nén ra đều được tính NGAY, vượt là ném
    BudgetExceeded giữa chừng (không đợi đọc xong file con).
    """
    budget = budget or Budget()
    try:
        if kind == "7z":
            yield from _7z(src, limit, list(passwords), budget)
        else:
            reader = {"zip": _zip, "rar": _rar}.get(kind, _tar)
            yield from reader(src, name, kind, limit, list(passwords), budget)
    except ArchiveError:
        raise
    except Exception as e:  # thư viện giải nén ném đủ loại lỗi với file hỏng/cố tình làm hỏng
        raise ArchiveError(f"{type(e).__name__}: {e}") from e


def _open(src):
    return io.BytesIO(src) if isinstance(src, bytes) else open(src, "rb")


def _read(fh, limit, budget):
    """Đọc từng khúc, tính ngân sách sau mỗi khúc; không tin kích thước khai báo: đọc tối đa limit + 1 byte."""
    chunks, size = [], 0
    while size <= limit:
        chunk = fh.read(min(CHUNK, limit + 1 - size))
        if not chunk:
            return b"".join(chunks), ""
        budget.take(len(chunk))
        chunks.append(chunk)
        size += len(chunk)
    return None, TOO_BIG


def _read_member(open_fn, encrypted, passwords, limit, budget):
    """Đọc một file con, thử lần lượt các mật khẩu nếu file bị mã hóa."""
    for pwd in passwords if encrypted else [None]:
        try:
            with open_fn(pwd) as fh:
                return _read(fh, limit, budget)
        except Exception:
            if not encrypted:
                raise
    return None, LOCKED


def _zip_directory(f):
    """(số entry, kích thước danh mục) đọc từ bản ghi cuối file ZIP (EOCD, ZIP64), KHÔNG nạp danh mục."""
    f.seek(0, os.SEEK_END)
    size = f.tell()
    f.seek(max(0, size - 65536 - 22))
    tail = f.read()
    i = tail.rfind(b"PK\x05\x06")
    if i < 0 or len(tail) < i + 16:
        return None  # để zipfile tự báo file hỏng
    count, cd_size = struct.unpack_from("<HI", tail, i + 10)
    loc = i - 20
    if (count == 0xFFFF or cd_size == 0xFFFFFFFF) and loc >= 0 and tail[loc:loc + 4] == b"PK\x06\x07":
        f.seek(struct.unpack_from("<Q", tail, loc + 8)[0])
        rec = f.read(56)
        if rec[:4] == b"PK\x06\x06" and len(rec) == 56:
            count, cd_size = struct.unpack_from("<QQ", rec, 32)
    return count, cd_size


def _zip(src, name, kind, limit, passwords, budget):
    f = _open(src)
    try:
        directory = _zip_directory(f)
        if directory:  # chặn TRƯỚC khi zipfile nạp toàn bộ metadata vào RAM
            count, cd_size = directory
            budget.check_entries(count)
            room = max(0, budget.max_files - budget.files)
            if cd_size > room * ZIP_CD_BYTES_PER_ENTRY + 65536:
                budget.check_entries(budget.max_files + 1, f"danh mục file {cd_size >> 10} KB – quá lớn")
        f.seek(0)
        zf = zipfile.ZipFile(f)
    except BaseException:
        f.close()
        raise
    with f, zf:
        for info in zf.infolist():
            budget.entry()
            if info.is_dir():
                continue
            m = Member(info.filename, size=info.file_size, packed=info.compress_size,
                       encrypted=bool(info.flag_bits & 1))
            if info.file_size > limit:
                m.note = TOO_BIG
                budget.take(info.file_size)  # không đọc nhưng vẫn tính: tránh lách ngân sách bằng file "quá lớn"
            else:
                try:
                    m.data, m.note = _read_member(
                        lambda pwd: zf.open(info, pwd=pwd.encode() if pwd else None),
                        m.encrypted, passwords, limit, budget)
                except Exception as e:  # một file con hỏng không được làm dừng cả file nén
                    m.note = f"lỗi đọc: {e}"
            yield m


def _tar(src, name, kind, limit, passwords, budget):
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
            budget.entry()
            with opener(f) as fh:
                data, note = _read(fh, limit, budget)
            inner = os.path.splitext(os.path.basename(name))[0] or "data"
            yield Member(inner, data, len(data or b""), note=note)
            return
        with tf:
            for ti in tf:  # tarfile đọc lần lượt từng header: dừng là không đọc tiếp
                budget.entry()
                if ti.isdir():
                    continue
                m = Member(ti.name, size=ti.size, link=ti.linkname if ti.issym() or ti.islnk() else "")
                if ti.isfile():
                    if ti.size > limit:
                        m.note = TOO_BIG
                        # tính TRƯỚC khi tarfile phải giải nén bỏ qua phần dữ liệu này (tốn CPU thật)
                        budget.take(ti.size)
                    else:
                        m.data, m.note = _read(tf.extractfile(ti), limit, budget)
                yield m


def _7z_factory(limit, budget):
    """Bộ ghi của py7zr tính ngân sách ngay khi từng khúc được giải nén ra."""
    from py7zr.io import BytesIOFactory, Py7zBytesIO

    class Counted(Py7zBytesIO):
        def write(self, s):
            budget.take(len(s))  # BudgetExceeded làm py7zr dừng giải nén ngay
            return super().write(s)

    class Factory(BytesIOFactory):
        def create(self, filename):
            self.products[filename] = Counted(filename, self.limit)
            return self.products[filename]

    return Factory(limit + 1)


def _7z(src, limit, passwords, budget):
    """Giải nén 7z theo từng lô <= limit byte; mỗi khúc giải nén ra đều được tính vào ngân sách ngay.

    shortcut: py7zr đọc TOÀN BỘ danh mục file khi mở (không duyệt lần lượt được) nên giới hạn số entry chỉ
    áp dụng ngay sau khi mở; danh mục 7z cực lớn vẫn tốn RAM lúc mở → dùng --isolate --worker-memory.
    """
    import py7zr

    # 1. Tìm mật khẩu đúng bằng cách giải nén thử file nhỏ nhất
    chosen, infos, encrypted = None, None, False
    for pwd in [None, *passwords]:
        try:
            with _open(src) as f, py7zr.SevenZipFile(f, password=pwd) as z:
                listing = z.list()
                budget.check_entries(len(listing))
                infos = [i for i in listing if not i.is_directory]
                encrypted = z.needs_password()
                if encrypted and pwd is None:
                    continue
                probe = min((i for i in infos if i.uncompressed <= limit), key=lambda i: i.uncompressed,
                            default=None)
                if probe:
                    z.extract(targets=[probe.filename], factory=_7z_factory(limit, budget))
            chosen = pwd
            break
        except py7zr.exceptions.PasswordRequired:
            continue
        except Exception:
            if pwd is None:
                raise
            continue  # sai mật khẩu → thử mật khẩu tiếp theo
    if infos is None:
        raise EncryptedArchive("7z bị mã hóa cả danh sách file" + (", sai mật khẩu" if passwords else ""))
    for _ in range(len(listing) - len(infos)):
        budget.entry()  # thư mục cũng tính vào số entry
    if encrypted and chosen is None:
        for i in infos:
            budget.entry()
            yield Member(i.filename, size=i.uncompressed, packed=i.compressed, encrypted=True, note=LOCKED)
        return

    def extract(batch):
        factory = _7z_factory(limit, budget)
        with _open(src) as f, py7zr.SevenZipFile(f, password=chosen) as z:
            z.extract(targets=[i.filename for i in batch], factory=factory)
        budget.check()  # phòng khi py7zr giải nén song song trong luồng phụ và không chuyển lỗi ra ngoài
        for i in batch:
            m = Member(i.filename, size=i.uncompressed, packed=i.compressed, encrypted=encrypted)
            if i.filename in factory.products:
                buf = factory.get(i.filename)
                buf.seek(0)
                data = buf.read()  # đã tính ngân sách lúc ghi
                m.data, m.note = (None, TOO_BIG) if len(data) > limit else (data, "")
            else:
                m.note = "không giải nén được"
            yield m

    # 2. Gom file thành lô; một lô chỉ được giải nén khi còn đủ ngân sách cho nó
    batch, pending = [], 0
    for i in infos:
        budget.entry()
        if i.uncompressed > limit:
            budget.take(i.uncompressed)  # không đọc nhưng py7zr vẫn phải giải nén qua nó trong khối solid
            yield Member(i.filename, size=i.uncompressed, packed=i.compressed, encrypted=encrypted, note=TOO_BIG)
            continue
        if batch and pending + i.uncompressed > min(limit, budget.remaining()):
            yield from extract(batch)
            batch, pending = [], 0
        batch.append(i)
        pending += i.uncompressed
    if batch:
        yield from extract(batch)


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


def _rar(src, name, kind, limit, passwords, budget):
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
            # shortcut: rarfile đọc toàn bộ header khi mở (không duyệt lần lượt được); kích thước file nén
            # đầu vào đã bị giới hạn nên danh mục cũng bị chặn. Muốn chặt hơn: --isolate --worker-memory.
            for info in rf.infolist():
                budget.entry()
                if info.is_dir():
                    continue
                m = Member(info.filename, size=info.file_size, packed=info.compress_size,
                           encrypted=info.needs_password())
                if info.file_size > limit:
                    m.note = TOO_BIG
                    budget.take(info.file_size)
                else:
                    try:
                        m.data, m.note = _read_member(
                            lambda pwd: rf.open(info, pwd=pwd), m.encrypted, passwords, limit, budget)
                    except rarfile.RarCannotExec:
                        m.note = "cần cài unrar hoặc 7-Zip để đọc nội dung RAR"
                    except Exception as e:
                        m.note = f"lỗi đọc: {e}"
                yield m
