"""Điều phối việc quét: đọc file, đi vào file nén lồng nhau, chấm điểm từng file."""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import engines, malwarebazaar, rules
from .extract import ARCHIVE_KINDS, ArchiveError, EncryptedArchive, archive_kind, iter_members
from .rules import CRITICAL, HIGH, LOW, MEDIUM, Finding

DATA_DIR = Path(__file__).parent / "data"
MB = 1 << 20
BOMB_MIN_SIZE = 50 * MB  # chỉ xét tỷ lệ nén với file con lớn, tránh báo nhầm file text nhỏ
VERDICTS = ("clean", "suspicious", "malicious")


def score_and_verdict(findings) -> tuple[int, str]:
    # Mỗi nhóm hành vi chỉ tính mức nặng nhất: nhiều bằng chứng cho CÙNG một hành vi không cộng dồn,
    # còn nhiều hành vi KHÁC nhau (vd. ghi phím + gửi dữ liệu ra ngoài) thì cộng lại.
    worst = {}
    for f in findings:
        worst[f.category] = max(worst.get(f.category, 0), f.severity)
    score = min(100, sum(rules.SEVERITY_SCORE[s] for s in worst.values()))
    if score >= 80 or CRITICAL in worst.values():
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
        return score_and_verdict(self.findings)[1]

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
        return max((f.verdict for f in self.files), key=VERDICTS.index, default="clean")

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


class Scanner:
    def __init__(self, *, passwords=(), max_depth=5, max_file_mb=256, max_total_mb=4096,
                 max_files=20000, max_ratio=100, timeout=300, hash_files=(), yara_paths=(),
                 use_yara=True, use_clamav=True):
        self.passwords = list(passwords)
        self.max_depth = max_depth
        self.max_file = max_file_mb * MB
        self.max_total = max_total_mb * MB
        self.max_files = max_files
        self.max_ratio = max_ratio
        self.timeout = timeout
        cache = malwarebazaar.cache_path()
        hash_status = (f"cache MalwareBazaar {time.strftime('%Y-%m-%d', time.localtime(cache.stat().st_mtime))}"
                       if cache.exists() else "chạy --update-hashes để tải thêm từ MalwareBazaar")
        # data/*.txt: known_bad.txt (EICAR) + malwarebazaar.txt do GitHub Actions cập nhật hằng tuần
        self.hashes = rules.load_hashes([*sorted(DATA_DIR.glob("*.txt")), *([cache] if cache.exists() else []),
                                         *hash_files])
        self.yara, yara_status = (engines.load_yara([DATA_DIR / "rules", *yara_paths])
                                  if use_yara else ([], "tắt"))
        self.use_clamav = use_clamav and engines.find_clamav() is not None
        self.engines = {
            "heuristic": "bật",
            "hash": f"{len(self.hashes)} mã băm ({hash_status})",
            "yara": yara_status,
            "clamav": "bật" if self.use_clamav else ("tắt" if not use_clamav else "chưa cài"),
        }

    def scan_path(self, path) -> Report:
        path = Path(path)
        report = Report(str(path))
        with open(path, "rb") as f:
            head = f.read(512)
        budget = self._budget()
        if archive_kind(head) or path.stat().st_size <= self.max_file:
            # file nén gốc được đọc thẳng từ đĩa, không nạp cả file vào RAM
            src = path if archive_kind(head) else path.read_bytes()
            self._scan(src, path.name, path.name, 0, report, budget)
        else:
            report.files.append(FileResult(path.name, "?", path.stat().st_size, note="quá lớn, không quét"))
            report.incomplete.append(f"{path.name}: lớn hơn {self.max_file // MB} MB")
        if self.use_clamav:
            found = engines.clamav_scan(path)
            if found is None:
                report.incomplete.append("ClamAV không chạy được")
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
            res.findings += rules.check_content(data, kind, name)
            res.findings += engines.yara_scan(self.yara, data)
        if kind in ARCHIVE_KINDS:
            if depth >= self.max_depth:
                res.findings.append(Finding("ARCHIVE.TOO_DEEP", MEDIUM, "archive_abuse",
                                            f"File nén lồng nhau quá {self.max_depth} tầng – dừng lại"))
                report.incomplete.append(f"{display}: lồng quá sâu")
            else:
                self._walk(kind, src, name, display, depth, res, report, budget)

    def _budget(self):
        """Ngân sách dùng chung cho MỌI tầng lồng nhau của một lần quét."""
        return {"files": 0, "bytes": 0, "deadline": time.monotonic() + self.timeout, "stopped": False}

    def _over_budget(self, budget, res, report, display):
        """True nếu đã vượt ngân sách; phát hiện chỉ được ghi một lần, ở tầng chạm ngưỡng đầu tiên."""
        if budget["stopped"]:
            return True
        if budget["files"] > self.max_files:
            f = Finding("ARCHIVE.TOO_MANY_FILES", MEDIUM, "archive_abuse",
                        f"Hơn {self.max_files} file bên trong – dừng quét")
        elif budget["bytes"] > self.max_total:
            f = Finding("ARCHIVE.BOMB_TOTAL", HIGH, "archive_abuse",
                        f"Tổng dung lượng giải nén vượt {self.max_total // MB} MB – nghi zip bomb")
        elif time.monotonic() >= budget["deadline"]:  # >=: đồng hồ Windows/Python 3.10 nhích theo nấc ~16 ms
            f = Finding("ARCHIVE.TIMEOUT", MEDIUM, "archive_abuse",
                        f"Quét quá {self.timeout} giây – dừng (file nén có thể được thiết kế để làm treo trình quét)")
        else:
            return False
        budget["stopped"] = True
        res.findings.append(f)
        report.incomplete.append(f"{display}: dừng – {f.title}")
        return True

    def _walk(self, kind, src, name, display, depth, res, report, budget):
        if self._over_budget(budget, res, report, display):
            return
        members = iter_members(kind, src, name, self.max_file, self.passwords,
                               remaining=lambda: self.max_total - budget["bytes"])
        try:
            for m in members:
                budget["files"] += 1
                # đếm byte THỰC TẾ đã đọc ra (header có thể khai man), hoặc kích thước khai báo nếu bỏ qua nội dung
                budget["bytes"] += max(m.size, len(m.data or b""))
                if self._over_budget(budget, res, report, display):
                    members.close()  # dừng hẳn bộ giải nén, không đọc thêm byte nào
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
        except EncryptedArchive as e:
            res.findings.append(Finding("ARCHIVE.ENCRYPTED", MEDIUM, "evasion",
                                        "Mã hóa cả danh sách file – không xem được bên trong", str(e)))
            report.incomplete.append(f"{display}: {e}")
        except ArchiveError as e:
            res.findings.append(Finding("ARCHIVE.CORRUPT", LOW, "archive_abuse",
                                        "File nén hỏng hoặc không đọc được", str(e)))
            report.incomplete.append(f"{display}: {e}")
