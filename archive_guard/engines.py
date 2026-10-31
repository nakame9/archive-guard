"""Engine bổ sung, không bắt buộc: YARA và ClamAV. Máy thiếu engine nào thì bỏ qua engine đó."""
from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from .rules import CRITICAL, HIGH, LOW, MEDIUM, Finding

_SEVERITY = {"low": LOW, "medium": MEDIUM, "high": HIGH, "critical": CRITICAL}


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
    for f in files:
        try:
            compiled.append(yara.compile(filepath=str(f)))
            loaded.append(f)
        except yara.Error as e:  # một file luật lỗi không làm hỏng cả bộ
            bad.append(f"{f.name}: {e}")
    status = f"{len(compiled)} file luật"
    return compiled, status + (f" (bỏ qua file lỗi: {'; '.join(bad)})" if bad else ""), loaded


def yara_scan(compiled, data: bytes, timeout: int = 60) -> list[Finding]:
    """meta trong luật: severity = low|medium|high|critical, category, description."""
    out = []
    for rules in compiled:
        for m in rules.match(data=data, timeout=timeout):
            meta = m.meta
            sev = _SEVERITY.get(str(meta.get("severity", "")).lower(), HIGH)
            confidence = str(meta.get("confidence", "")).lower()
            if confidence not in ("low", "medium", "high"):
                confidence = "high" if sev == CRITICAL else "medium"
            out.append(Finding(f"YARA.{m.rule}", sev, str(meta.get("category", "generic")),
                               str(meta.get("description", m.rule)), engine="yara", confidence=confidence,
                               attack=str(meta.get("attack", ""))))
    return out


def find_clamav() -> str | None:
    return shutil.which("clamdscan") or shutil.which("clamscan")


def clamav_scan(path, timeout: float = 900) -> list[Finding] | None:
    """Quét bằng ClamAV (ClamAV tự mở ZIP/RAR/7z… lồng nhau). None = không chạy được hoặc quá thời gian.

    timeout là thời gian tối đa cho CẢ lần gọi; khi hết giờ subprocess.run tự kill ClamAV.
    """
    deadline = time.monotonic() + timeout
    for cmd in ("clamdscan", "clamscan"):  # clamdscan nhanh nhưng cần daemon; lỗi thì dùng clamscan
        exe = shutil.which(cmd)
        if not exe:
            continue
        # clamscan mặc định bỏ qua file > 100 MB mà vẫn trả "sạch" → nâng lên mức tối đa ClamAV hỗ trợ (2 GB).
        # clamdscan lấy giới hạn từ clamd.conf (MaxFileSize, MaxScanSize), không đổi được từ đây.
        limits = ["--max-filesize=2047M", "--max-scansize=2047M"] if cmd == "clamscan" else []
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
