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
import queue
import struct
import tarfile
import tempfile
import threading
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


def _pe_overlay(data: bytes) -> int | None:
    """Vị trí bắt đầu phần dữ liệu gắn sau PE (overlay) = cuối section xa nhất; None nếu header PE không hợp lệ."""
    try:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            return None
        count, opt = struct.unpack_from("<2xH12xH", data, pe + 4)  # NumberOfSections, SizeOfOptionalHeader
        table = pe + 24 + opt
        # mỗi section 40 byte; SizeOfRawData + PointerToRawData ở byte 16–23 → cuối section
        return max((sum(struct.unpack_from("<II", data, table + 40 * i + 16)) for i in range(count)), default=None)
    except struct.error:
        return None


def has_trailing_zip(f) -> bool:
    """f (đã mở, seek được) kết thúc bằng một ZIP thật, kể cả khi có dữ liệu khác phía trước.

    Không dùng zipfile.is_zipfile: nó chỉ dò chuỗi PK\\x05\\x06, vốn xuất hiện ngẫu nhiên trong file PE sạch (vd.
    Squirrel-Mono.exe) và kéo theo một "danh mục" giả hàng GB. Ở đây đòi danh mục (PK\\x01\\x02) nằm ngay trước EOCD.
    """
    f.seek(0, os.SEEK_END)
    size = f.tell()
    base = max(0, size - 65536 - 22)
    f.seek(base)
    tail = f.read()
    i = tail.rfind(b"PK\x05\x06")
    if i < 0 or len(tail) < i + 22:
        return False
    count, end = struct.unpack_from("<HI", tail, i + 10)[0], i
    cd_size = struct.unpack_from("<I", tail, i + 12)[0]
    if tail[i - 20:i - 16] == b"PK\x06\x07" and tail[i - 76:i - 72] == b"PK\x06\x06":  # ZIP64
        cd_size, end, count = struct.unpack_from("<Q", tail, i - 76 + 40)[0], i - 76, 1
    start = base + end - cd_size
    if count == 0 or start < 0:
        return False
    f.seek(start)
    return f.read(4) == b"PK\x01\x02"


def embedded_archive(data: bytes, kind: str) -> tuple[str, bytes] | None:
    """File nén nằm sau dữ liệu khác (SFX, polyglot, vài byte rác ở đầu): 7-Zip/unzip vẫn mở được nên phải quét.

    Trả (loại, dữ liệu để giải nén) hoặc None. ZIP: zipfile tự dò danh mục ở cuối file và bù offset → đưa nguyên
    file. RAR/7z: tìm chữ ký trong overlay của PE (SFX) hoặc sau byte đầu của file nhị phân lạ → cắt từ chữ ký.
    """
    if kind in ARCHIVE_KINDS:
        return None
    if has_trailing_zip(io.BytesIO(data)):
        return "zip", data
    # ponytail: chỉ dò RAR/7z ở overlay PE và file nhị phân lạ; text/script/PDF chứa chữ ký nén chưa được xét
    start = _pe_overlay(data) if kind == "pe" else 1 if kind == "unknown" else None
    if start is None:
        return None
    for magic, inner in ((b"Rar!\x1a\x07", "rar"), (b"7z\xbc\xaf\x27\x1c", "7z")):
        i = data.find(magic, start)
        if i >= 0:
            return inner, data[i:]
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


_ZIP_METHODS = {0, 1, 6, 8, 9, 12, 14, 93, 95, 98, 99}


def zip_anomalies(src) -> tuple[list, list]:
    """Cấu trúc ZIP bất thường: (các cặp entry dùng chung vùng dữ liệu, tên các file có local header nhưng KHÔNG có
    trong danh mục). Chỉ gọi SAU khi đã duyệt file qua ngân sách (số entry đã được kiểm tra)."""
    import bisect
    import mmap

    with _open(src) as f, zipfile.ZipFile(f) as zf:
        buf = src if isinstance(src, bytes) else mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            ranges = []
            for info in zf.infolist():
                off = info.header_offset
                if buf[off:off + 4] == b"PK\x03\x04":
                    name_len, extra_len = struct.unpack_from("<HH", buf, off + 26)
                    ranges.append((off, off + 30 + name_len + extra_len + info.compress_size, info.filename))
            ranges.sort()
            overlaps = [(a[2], b[2]) for a, b in zip(ranges, ranges[1:]) if b[0] < a[1]]
            starts, ends, hidden = [r[0] for r in ranges], [r[1] for r in ranges], []
            pos = buf.find(b"PK\x03\x04")
            while pos != -1 and len(hidden) < 20:
                i = bisect.bisect_right(starts, pos) - 1
                if i < 0 or (starts[i] != pos and ends[i] <= pos):  # không thuộc vùng của entry nào (kể cả ZIP lồng)
                    name = _local_header_name(buf, pos)
                    if name is not None:
                        hidden.append(name)
                pos = buf.find(b"PK\x03\x04", pos + 1)
            return overlaps, hidden
        finally:
            if not isinstance(src, bytes):
                buf.close()


def _local_header_name(buf, pos):
    """Tên file nếu tại pos là một local header hợp lệ (lọc chuỗi PK\\x03\\x04 ngẫu nhiên trong dữ liệu nén)."""
    if pos + 30 > len(buf):
        return None
    version, _flags, method = struct.unpack_from("<HHH", buf, pos + 4)
    name_len, extra_len = struct.unpack_from("<HH", buf, pos + 26)
    raw = buf[pos + 30:pos + 30 + name_len]
    if version > 100 or method not in _ZIP_METHODS or not 0 < name_len <= 1024 or len(raw) < name_len \
            or b"\x00" in raw or pos + 30 + name_len + extra_len > len(buf):
        return None
    return raw.decode("utf-8", "replace")


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


class _Stop(BaseException):
    """Luồng chính không nhận thêm file nữa: dừng luồng giải nén."""


def _7z_stream(src, password, targets, limit, budget):
    """Giải nén 7z MỘT lượt (khối solid chỉ giải nén một lần) trong luồng phụ; trả lần lượt (tên, dữ liệu).

    Luồng phụ dừng ở cuối mỗi file cho tới khi luồng chính xử lý xong file đó: hai luồng không bao giờ chạy cùng
    lúc (Budget không cần khóa) và RAM chỉ giữ một file. Lỗi của luồng phụ, kể cả BudgetExceeded, được ném lại ở
    luồng chính.
    """
    import py7zr
    from py7zr.io import BytesIOFactory, Py7zBytesIO

    q, stop, done = queue.Queue(maxsize=1), threading.Event(), object()

    class Counted(Py7zBytesIO):
        def write(self, s):
            if stop.is_set():
                raise _Stop
            budget.take(len(s))
            return super().write(s)

        def close(self):  # py7zr >= 1.1.3 gọi khi giải nén xong (và kiểm CRC) một file
            if not stop.is_set():
                self.seek(0)
                q.put((self.filename, self.read()))
                q.join()  # chờ luồng chính quét xong file này

    class Factory(BytesIOFactory):
        def create(self, filename):
            return Counted(filename, self.limit)

    def run():
        try:
            with _open(src) as f, py7zr.SevenZipFile(f, password=password) as z:
                z.extract(targets=targets, factory=Factory(limit + 1))
            q.put(done)
        except BaseException as e:  # noqa: BLE001 – chuyển mọi lỗi (cả BudgetExceeded) sang luồng chính
            q.put(e)

    worker = threading.Thread(target=run, name="7z", daemon=True)
    worker.start()
    taken = False
    try:
        while True:
            item = q.get()
            taken = True
            if item is done:
                return
            if isinstance(item, BaseException):
                raise item
            yield item
            q.task_done()
            taken = False
    finally:
        stop.set()
        if taken:
            q.task_done()
        while worker.is_alive():  # nhả luồng phụ đang chờ; lần ghi kế tiếp của nó ném _Stop
            try:
                q.get(timeout=0.05)
                q.task_done()
            except queue.Empty:
                pass


def _7z(src, limit, passwords, budget):
    """Giải nén 7z một lượt; mỗi khúc giải nén ra đều được tính vào ngân sách ngay.

    shortcut: py7zr đọc TOÀN BỘ danh mục file khi mở (không duyệt lần lượt được) nên giới hạn số entry chỉ
    áp dụng ngay sau khi mở; danh mục 7z cực lớn vẫn tốn RAM lúc mở → dùng --isolate --worker-memory.
    """
    import py7zr

    # 1. Tìm mật khẩu đúng (chỉ khi file có mật khẩu) bằng cách giải nén thử file nhỏ nhất
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
                if encrypted and probe:
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

    # 2. File quá lớn: không đọc, nhưng py7zr vẫn phải giải nén qua chúng trong khối solid → tính trước
    wanted = {}
    for i in infos:
        budget.entry()
        if i.uncompressed > limit:
            budget.take(i.uncompressed)
            yield Member(i.filename, size=i.uncompressed, packed=i.compressed, encrypted=encrypted, note=TOO_BIG)
        else:
            wanted[i.filename] = i
    if not wanted:
        return
    # 3. Một lượt giải nén cho tất cả file còn lại
    for name, data in _7z_stream(src, chosen, list(wanted), limit, budget):
        i = wanted.pop(name, None)
        m = Member(name, size=i.uncompressed if i else len(data), packed=i.compressed if i else None,
                   encrypted=encrypted)
        m.data, m.note = (None, TOO_BIG) if len(data) > limit else (data, "")
        yield m
    for i in wanted.values():  # py7zr không trả file này (vd. phiên bản không gọi close())
        yield Member(i.filename, size=i.uncompressed, packed=i.compressed, encrypted=encrypted,
                     note="không giải nén được")


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
