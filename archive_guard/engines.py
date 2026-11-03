"""Engine bổ sung, không bắt buộc: YARA và ClamAV. Máy thiếu engine nào thì bỏ qua engine đó."""
from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from .rules import CRITICAL, HIGH, LOW, MEDIUM, Finding

_SEVERITY = {"low": LOW, "medium": MEDIUM, "high": HIGH, "critical": CRITICAL}
# Biến ngoài mà luật của signature-base/THOR dùng (tên file…); để trống: ta quét nội dung, không quét đường dẫn
_EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}


def load_yara(paths):
    """Biên dịch từng file luật .yar/.yara; trả về (luật đã biên dịch, trạng thái, các file nạp được)."""
    try:
        import yara
    except ImportError:
        return [], "chưa cài (pip install yara-python)", []
    files = []
    for p in map(Path, paths):
        files += [p] if p.is_file() else sorted([*p.rglob("*.yar"), *p.rglob("*.yara")])
    compiled, bad, loaded = [], [], []
    try:  # biên dịch chung: một lượt quét cho mọi luật (hàng trăm file luật cộng đồng)
        compiled.append(yara.compile(filepaths={f"{i}:{f.stem}": str(f) for i, f in enumerate(files)},
                                     externals=_EXTERNALS))
        loaded = files
    except yara.Error:
        for f in files:  # có file lỗi: biên dịch từng file, bỏ file lỗi, không làm hỏng cả bộ
            try:
                compiled.append(yara.compile(filepath=str(f), externals=_EXTERNALS))
                loaded.append(f)
            except yara.Error as e:
                bad.append(f"{f.name}: {e}")
    if not files:
        compiled = []
    status = f"{len(loaded)} file luật"
    return compiled, status + (f" (bỏ qua file lỗi: {'; '.join(bad)})" if bad else ""), loaded


def yara_scan(compiled, data: bytes, timeout: int = 60) -> list[Finding]:
    """meta trong luật: severity = low|medium|high|critical, category, description."""
    out = []
    for rules in compiled:
        for m in rules.match(data=data, timeout=timeout):
            meta = m.meta
            sev = _SEVERITY.get(str(meta.get("severity", "")).lower()) or _score_severity(meta.get("score")) or HIGH
            confidence = str(meta.get("confidence", "")).lower()
            if confidence not in ("low", "medium", "high"):
                confidence = "high" if sev == CRITICAL else "medium"
            # luật cộng đồng (signature-base: meta score, không có category) là chữ ký họ mã độc cụ thể
            category = meta.get("category") or ("known_malware" if "score" in meta else "generic")
            # Detection Rule License 1.1: thông báo khi luật khớp phải giữ tên tác giả luật
            detail = f"luật {m.rule}" + (f", tác giả: {meta['author']}" if meta.get("author") else "")
            out.append(Finding(f"YARA.{m.rule}", sev, str(category), str(meta.get("description", m.rule)), detail,
                               engine="yara", confidence=confidence, attack=str(meta.get("attack", ""))))
    return out


def _score_severity(score):
    """Thang score của signature-base/THOR: >= 80 cảnh báo mạnh, 60–79 đáng ngờ, < 60 chỉ để lưu ý."""
    try:
        score = int(score)
    except (TypeError, ValueError):
        return None
    return CRITICAL if score >= 80 else HIGH if score >= 60 else MEDIUM


VT_URL = "https://www.virustotal.com/api/v3/files/"
VT_MIN_ENGINES = 5  # ít hơn thường là báo nhầm của một vài engine


def virustotal_lookup(sha256: str, api_key: str, opener=None) -> dict | None:
    """Tra MÃ BĂM trên VirusTotal (không gửi file). None = VirusTotal chưa biết file này.

    API miễn phí giới hạn 4 lượt/phút: gặp HTTP 429 thì chờ 60 giây rồi thử lại một lần.
    """
    import json
    import urllib.error
    import urllib.request
    opener = opener or urllib.request.urlopen
    req = urllib.request.Request(VT_URL + sha256, headers={"x-apikey": api_key, "User-Agent": "archive-guard"})
    for attempt in range(2):
        try:
            with opener(req, timeout=60) as r:
                stats = json.load(r)["data"]["attributes"]["last_analysis_stats"]
            return {"malicious": int(stats.get("malicious", 0)), "total": sum(int(v) for v in stats.values())}
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 429 and attempt == 0:
                time.sleep(60)
                continue
            raise
    return None


def find_clamav() -> str | None:
    return shutil.which("clamdscan") or shutil.which("clamscan")


def clamav_scan(path, timeout: float = 900, commands=("clamdscan", "clamscan")) -> list[Finding] | None:
    """Quét bằng ClamAV (ClamAV tự mở ZIP/RAR/7z… lồng nhau). None = không chạy được hoặc quá thời gian.

    timeout là thời gian tối đa cho CẢ lần gọi; khi hết giờ subprocess.run tự kill ClamAV.
    Chế độ cô lập: process cha chỉ gọi clamdscan, worker chỉ gọi clamscan (worker không được mở socket).
    """
    deadline = time.monotonic() + timeout
    for cmd in commands:  # clamdscan nhanh nhưng cần daemon; lỗi thì dùng clamscan
        exe = shutil.which(cmd)
        if not exe:
            continue
        # clamscan mặc định bỏ qua file > 100 MB mà vẫn trả "sạch" → nâng lên mức tối đa ClamAV hỗ trợ (2 GB).
        # clamdscan lấy giới hạn từ clamd.conf (MaxFileSize, MaxScanSize), không đổi được từ đây.
        # --fdpass: clamd nhận file descriptor, không cần quyền đọc file của người dùng
        limits = ["--max-filesize=2047M", "--max-scansize=2047M"] if cmd == "clamscan" else ["--fdpass"]
        left = deadline - time.monotonic()  # clamdscan lỗi rồi chuyển sang clamscan vẫn dùng chung một mốc
        if left <= 0:
            return None
        try:
            p = subprocess.run([exe, "--no-summary", "--infected", *limits, str(path)],
                               capture_output=True, text=True, timeout=left)
        except subprocess.TimeoutExpired:
            return None  # không thử tiếp clamscan: sẽ vượt quá thời gian còn lại
        except OSError:
            continue
        if p.returncode in (0, 1):  # 0 = sạch, 1 = có mã độc, 2 = lỗi
            return [Finding("CLAMAV", CRITICAL, "known_malware",
                            "ClamAV: " + line.rsplit(": ", 1)[-1].removesuffix(" FOUND"),
                            line.rsplit(": ", 1)[0], "clamav")
                    for line in p.stdout.splitlines() if line.endswith(" FOUND")]
    return None
