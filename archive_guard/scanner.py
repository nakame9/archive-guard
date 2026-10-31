"""Điều phối việc quét: đọc file, đi vào file nén lồng nhau, chấm điểm từng file."""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import engines, malwarebazaar, rules
from .extract import (
    ARCHIVE_KINDS,
    ArchiveError,
    Budget,
    BudgetExceeded,
    EncryptedArchive,
    archive_kind,
    iter_members,
    unsupported_container,
)
from .rules import CRITICAL, HIGH, LOW, MEDIUM, Finding

DATA_DIR = Path(__file__).parent / "data"
MB = 1 << 20
BOMB_MIN_SIZE = 50 * MB  # chỉ xét tỷ lệ nén với file con lớn, tránh báo nhầm file text nhỏ
# "incomplete": không phát hiện gì NHƯNG có phần chưa kiểm tra được → không được coi là sạch
VERDICTS = ("clean", "incomplete", "suspicious", "malicious")


# Số nhóm hành vi KHÁC nhau mà chỉ dấu "khả năng" (confidence low) phải đủ để được tính khi không có bằng chứng
# nào mạnh hơn. Hiệu chỉnh trên bộ phần mềm sạch đã thấy (benchmark/benign-corpus.txt, holdout-corpus-1.txt),
# KHÔNG trên bộ kiểm tra cuối – xem docs/BENCHMARK.md, vòng 3.
CAPABILITY_MIN_CATEGORIES = 3


def score_and_verdict(findings) -> tuple[int, str]:
    """Điểm 0–100 và kết luận. severity quyết định điểm; confidence quyết định có được tính và mức kết luận.

    - Chỉ có "khả năng" (API mà phần mềm hợp pháp cũng dùng) ở ít nhóm hành vi → không tính, kết luận sạch.
    - "nguy hiểm" cần ≥ 2 bằng chứng độc lập: 2 luật medium/high khác nhau, hoặc 1 luật + các khả năng ở nhóm
      khác (mỗi nhóm tính ½) – trừ phát hiện CRITICAL có độ tin cậy cao (mã băm, ClamAV, YARA critical).
    """
    strong = {f.rule for f in findings if f.confidence != "low"}
    weak_cats = {f.category for f in findings if f.confidence == "low" and f.category != "generic"}
    if not strong and len(weak_cats) < CAPABILITY_MIN_CATEGORIES:
        return 0, "clean"
    # Mỗi nhóm hành vi tính mức nặng nhất (+1 bậc nếu có ≥ 2 luật mạnh khác nhau cùng nhóm);
    # nhiều hành vi KHÁC nhau (vd. ghi phím + gửi dữ liệu ra ngoài) thì cộng lại.
    worst, rules_in = {}, {}
    for f in findings:
        worst[f.category] = max(worst.get(f.category, 0), f.severity)
        if f.confidence != "low":
            rules_in.setdefault(f.category, set()).add(f.rule)
    score = min(100, sum(rules.SEVERITY_SCORE[s] + (30 if len(rules_in.get(c, ())) >= 2 else 0)
                         for c, s in worst.items()))
    if any(f.severity == CRITICAL and f.confidence == "high" for f in findings):
        return 100, "malicious"
    if score >= 80 and len(strong) + 0.5 * len(weak_cats) >= 2:
        return score, "malicious"
    return score, "suspicious" if score >= 30 else "clean"


@dataclass
class FileResult:
    path: str  # vd: "goc.zip > thu_muc/ben_trong.zip > virus.exe"
    kind: str
    size: int
    sha256: str = ""
    findings: list = field(default_factory=list)
    note: str = ""

    @property
    def score(self):
        return score_and_verdict(self.findings)[0]

    @property
    def verdict(self):
        v = score_and_verdict(self.findings)[1]
        return "incomplete" if v == "clean" and self.note else v

    def to_dict(self):
        return {"path": self.path, "kind": self.kind, "size": self.size, "sha256": self.sha256,
                "score": self.score, "verdict": self.verdict, "note": self.note,
                "findings": [f.to_dict() for f in self.findings]}


@dataclass
class Report:
    target: str
    files: list = field(default_factory=list)
    incomplete: list = field(default_factory=list)  # những phần không kiểm tra được

    @property
    def verdict(self):
        v = max((f.verdict for f in self.files), key=VERDICTS.index, default="clean")
        return "incomplete" if v == "clean" and self.incomplete else v

    @property
    def categories(self):
        return sorted({x.category for f in self.files if f.verdict != "clean" for x in f.findings
                       if x.severity >= MEDIUM})

    def to_dict(self):
        return {"target": self.target, "verdict": self.verdict, "categories": self.categories,
                "complete": not self.incomplete, "incomplete": self.incomplete, "files": [f.to_dict() for f in self.files]}


def _digests(src) -> dict:
    hs = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    if isinstance(src, bytes):
        for h in hs.values():
            h.update(src)
    else:
        with open(src, "rb") as f:
            for chunk in iter(lambda: f.read(MB), b""):
                for h in hs.values():
                    h.update(chunk)
    return {k: h.hexdigest() for k, h in hs.items()}


def _normalized(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")  # Git trên Windows có thể đổi xuống dòng → cùng luật, cùng phiên bản


def rules_fingerprint(hashes: dict, yara_files) -> dict:
    """Phiên bản bộ luật tự sinh từ NỘI DUNG luật: không phải nhớ tăng số bằng tay.

    heuristic = rules.py + scanner.py (chỉ dấu, ngưỡng điểm); yara = nội dung các file luật đã nạp;
    hashes = danh sách mã băm kèm tên họ. Đổi bất kỳ phần nào → phiên bản đổi.
    """
    def h(parts):
        d = hashlib.sha256()
        for p in parts:
            d.update(hashlib.sha256(p).digest())
        return d.hexdigest()[:12]

    here = Path(__file__).parent
    parts = {
        "heuristic": h(_normalized((here / f).read_bytes()) for f in ("rules.py", "scanner.py")),
        "yara": h(sorted(hashlib.sha256(_normalized(Path(f).read_bytes())).digest() for f in yara_files)),
        "hashes": h([("\n".join(f"{k} {v}" for k, v in sorted(hashes.items()))).encode()]),
    }
    parts["all"] = h([v.encode() for v in parts.values()])
    return parts


class Scanner:
    def __init__(self, *, passwords=(), max_depth=5, max_file_mb=256, max_total_mb=4096,
                 max_files=20000, max_ratio=100, timeout=300, max_archive_mb=4096, hash_files=(), yara_paths=(),
                 use_yara=True, use_clamav=True):
        self.passwords = list(passwords)
        self.max_depth = max_depth
        self.max_file = max_file_mb * MB
        self.max_total = max_total_mb * MB
        self.max_files = max_files
        self.max_ratio = max_ratio
        self.timeout = timeout
        self.max_archive = max_archive_mb * MB
        cache = malwarebazaar.cache_path()
        hash_status = (f"cache MalwareBazaar {time.strftime('%Y-%m-%d', time.localtime(cache.stat().st_mtime))}"
                       if cache.exists() else "chạy --update-hashes để tải thêm từ MalwareBazaar")
        # data/*.txt: known_bad.txt (EICAR) + malwarebazaar.txt do GitHub Actions cập nhật hằng tuần
        self.hashes = rules.load_hashes([*sorted(DATA_DIR.glob("*.txt")), *([cache] if cache.exists() else []),
                                         *hash_files])
        self.yara, yara_status, yara_files = (engines.load_yara([DATA_DIR / "rules", *yara_paths])
                                              if use_yara else ([], "tắt", []))
        self.use_clamav = use_clamav and engines.find_clamav() is not None
        self.engines = {
            "heuristic": "bật",
            "hash": f"{len(self.hashes)} mã băm ({hash_status})",
            "yara": yara_status,
            "clamav": "bật" if self.use_clamav else ("tắt" if not use_clamav else "chưa cài"),
        }
        self.rules_components = rules_fingerprint(self.hashes, yara_files)
        self.rules_version = self.rules_components["all"]

    def scan_path(self, path) -> Report:
        path = Path(path)
        report = Report(str(path))
        with open(path, "rb") as f:
            head = f.read(512)
        budget = self._budget()
        size = path.stat().st_size
        if archive_kind(head) and size > self.max_archive:
            report.files.append(FileResult(path.name, archive_kind(head), size, note="file nén quá lớn, không quét"))
            report.incomplete.append(f"{path.name}: file nén lớn hơn {self.max_archive // MB} MB (--max-archive-size)")
        elif archive_kind(head) or size <= self.max_file:
            # file nén gốc được đọc thẳng từ đĩa, không nạp cả file vào RAM
            src = path if archive_kind(head) else path.read_bytes()
            self._scan(src, path.name, path.name, 0, report, budget)
        else:
            report.files.append(FileResult(path.name, "?", path.stat().st_size, note="quá lớn, không quét"))
            report.incomplete.append(f"{path.name}: lớn hơn {self.max_file // MB} MB")
        if self.use_clamav:
            left = budget.deadline - time.monotonic()  # ClamAV dùng phần thời gian còn lại, không hơn
            found = engines.clamav_scan(path, timeout=left) if left >= 1 else None
            if found is None:
                report.incomplete.append(
                    "ClamAV không chạy được hoặc hết thời gian quét (thiếu cơ sở dữ liệu? chạy freshclam, "
                    "tăng --timeout, hoặc dùng --no-clamav)")
            else:
                report.files[0].findings += found
        return report

    def scan_bytes(self, data: bytes, name: str = "data") -> Report:
        report = Report(name)
        self._scan(data, name, name, 0, report, self._budget())
        return report

    def _scan(self, src, name, display, depth, report, budget):
        """src: nội dung file (bytes) hoặc đường dẫn tới file nén gốc."""
        if isinstance(src, bytes):
            data, size, kind = src, len(src), rules.file_kind(src, name)
        else:
            with open(src, "rb") as f:
                data, size, kind = None, src.stat().st_size, archive_kind(f.read(512))
        digests = _digests(src)
        res = FileResult(display, kind, size, digests["sha256"])
        report.files.append(res)
        res.findings += rules.check_name(name, in_archive=depth > 0)
        known = next((h for h in digests.values() if h in self.hashes), None)
        if known:
            family = self.hashes[known]
            res.findings.append(Finding(
                "HASH.KNOWN_BAD", CRITICAL, malwarebazaar.CATEGORY_OF.get(family.lower(), "known_malware"),
                "Trùng mã băm với mẫu mã độc đã biết" + (f": {family}" if family else ""), engine="hash"))
        if data is not None:
            for engine, run in (("heuristic", lambda: rules.check_content(data, kind, name)),
                                ("YARA", lambda: engines.yara_scan(self.yara, data, timeout=max(
                                    1, min(60, int(budget.deadline - time.monotonic())))))):
                try:
                    res.findings += run()
                except Exception as e:  # engine lỗi/timeout KHÔNG được coi là sạch
                    self._not_checked(res, report, display, f"{engine} lỗi: {type(e).__name__}: {e}")
            fmt = unsupported_container(data) if kind not in ARCHIVE_KINDS else None
            if fmt:
                self._not_checked(res, report, display, f"định dạng {fmt} chưa được giải nén, chỉ quét dạng thô")
        if kind in ARCHIVE_KINDS:
            if depth >= self.max_depth:
                res.findings.append(Finding("ARCHIVE.TOO_DEEP", MEDIUM, "archive_abuse",
                                            f"File nén lồng nhau quá {self.max_depth} tầng – dừng lại"))
                report.incomplete.append(f"{display}: lồng quá sâu")
            else:
                self._walk(kind, src, name, display, depth, res, report, budget)

    @staticmethod
    def _not_checked(res, report, display, why):
        res.note = "; ".join(filter(None, [res.note, why]))
        report.incomplete.append(f"{display}: {why}")

    def _budget(self):
        """Ngân sách dùng chung cho MỌI tầng lồng nhau của một lần quét."""
        return Budget(self.max_files, self.max_total, self.timeout)

    def _stop(self, budget, e, res, report, display):
        """Ghi phát hiện vượt ngân sách đúng MỘT lần, ở tầng chạm ngưỡng đầu tiên."""
        if budget.stopped:
            return
        budget.stopped = True
        f = {"files": Finding("ARCHIVE.TOO_MANY_FILES", MEDIUM, "archive_abuse",
                              f"Hơn {self.max_files} entry bên trong – dừng quét", e.detail),
             "bytes": Finding("ARCHIVE.BOMB_TOTAL", HIGH, "archive_abuse",
                              f"Tổng dung lượng giải nén vượt {self.max_total // MB} MB – nghi zip bomb", e.detail),
             "time": Finding("ARCHIVE.TIMEOUT", MEDIUM, "archive_abuse",
                             f"Quét quá {self.timeout} giây – dừng (file nén có thể được thiết kế để làm treo trình quét)",
                             e.detail)}[e.kind]
        res.findings.append(f)
        report.incomplete.append(f"{display}: dừng – {f.title}")

    def _walk(self, kind, src, name, display, depth, res, report, budget):
        if budget.stopped:
            return
        members = iter_members(kind, src, name, self.max_file, self.passwords, budget)
        try:
            for m in members:
                if budget.stopped:  # một tầng con đã hết ngân sách → dừng cả cây
                    return
                child = f"{display} > {m.name}"
                if m.packed and m.size >= BOMB_MIN_SIZE and m.size / m.packed > self.max_ratio:
                    res.findings.append(Finding("ARCHIVE.BOMB_RATIO", HIGH, "archive_abuse",
                                                f"Tỷ lệ nén bất thường {m.size // m.packed}:1 – nghi zip bomb", m.name))
                    m.data, m.note = None, "bỏ qua nội dung (nghi zip bomb)"
                if m.data is not None:
                    self._scan(m.data, m.name, child, depth + 1, report, budget)
                    continue
                r = FileResult(child, "?", m.size, note=m.note)
                r.findings += rules.check_name(m.name, True, m.link)
                if m.encrypted and m.note:
                    runnable = rules.ext_of(m.name) in rules.RUNNABLE_EXTS
                    r.findings.append(Finding(
                        "ARCHIVE.ENCRYPTED_EXEC" if runnable else "ARCHIVE.ENCRYPTED",
                        MEDIUM if runnable else LOW, "evasion",
                        "File thực thi bị đặt mật khẩu – thủ thuật né antivirus" if runnable
                        else "Nội dung bị đặt mật khẩu, chưa kiểm tra được (dùng --password)"))
                if m.note:
                    report.incomplete.append(f"{child}: {m.note}")
                report.files.append(r)
        except BudgetExceeded as e:  # ném ra NGAY trong lúc giải nén, giữa chừng một file con
            self._stop(budget, e, res, report, display)
        except EncryptedArchive as e:
            res.findings.append(Finding("ARCHIVE.ENCRYPTED", MEDIUM, "evasion",
                                        "Mã hóa cả danh sách file – không xem được bên trong", str(e)))
            self._not_checked(res, report, display, str(e))
        except ArchiveError as e:
            res.findings.append(Finding("ARCHIVE.CORRUPT", LOW, "archive_abuse",
                                        "File nén hỏng hoặc không đọc được", str(e)))
            self._not_checked(res, report, display, f"không đọc được: {e}")
        finally:
            members.close()  # dừng hẳn bộ giải nén ở mọi lối thoát, không đọc thêm byte nào
