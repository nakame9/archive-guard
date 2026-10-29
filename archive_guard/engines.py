"""Engine bổ sung, không bắt buộc: YARA và ClamAV. Máy thiếu engine nào thì bỏ qua engine đó."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .rules import CRITICAL, HIGH, LOW, MEDIUM, Finding

_SEVERITY = {"low": LOW, "medium": MEDIUM, "high": HIGH, "critical": CRITICAL}


def load_yara(paths):
    """Biên dịch từng file luật .yar/.yara; trả về (danh sách luật, trạng thái để hiển thị)."""
    try:
        import yara
    except ImportError:
        return [], "chưa cài (pip install yara-python)"
    files = []
    for p in map(Path, paths):
        files += [p] if p.is_file() else sorted([*p.rglob("*.yar"), *p.rglob("*.yara")])
    compiled, bad = [], []
    for f in files:
        try:
            compiled.append(yara.compile(filepath=str(f)))
        except yara.Error as e:  # một file luật lỗi không làm hỏng cả bộ
            bad.append(f"{f.name}: {e}")
    status = f"{len(compiled)} file luật"
    return compiled, status + (f" (bỏ qua file lỗi: {'; '.join(bad)})" if bad else "")


def yara_scan(compiled, data: bytes) -> list[Finding]:
    """meta trong luật: severity = low|medium|high|critical, category, description."""
    out = []
    for rules in compiled:
        for m in rules.match(data=data, timeout=60):
            meta = m.meta
            out.append(Finding(f"YARA.{m.rule}", _SEVERITY.get(str(meta.get("severity", "")).lower(), HIGH),
                               str(meta.get("category", "generic")), str(meta.get("description", m.rule)),
                               engine="yara"))
    return out


def find_clamav() -> str | None:
    return shutil.which("clamdscan") or shutil.which("clamscan")


def clamav_scan(path) -> list[Finding] | None:
    """Quét bằng ClamAV (ClamAV tự mở ZIP/RAR/7z… lồng nhau). None = không chạy được ClamAV."""
    for cmd in ("clamdscan", "clamscan"):  # clamdscan nhanh nhưng cần daemon; lỗi thì dùng clamscan
        exe = shutil.which(cmd)
        if not exe:
            continue
        # clamscan mặc định bỏ qua file > 100 MB mà vẫn trả "sạch" → nâng lên mức tối đa ClamAV hỗ trợ (2 GB).
        # clamdscan lấy giới hạn từ clamd.conf (MaxFileSize, MaxScanSize), không đổi được từ đây.
        limits = ["--max-filesize=2047M", "--max-scansize=2047M"] if cmd == "clamscan" else []
        try:
            p = subprocess.run([exe, "--no-summary", "--infected", *limits, str(path)],
                               capture_output=True, text=True, timeout=900)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if p.returncode in (0, 1):  # 0 = sạch, 1 = có mã độc, 2 = lỗi
            return [Finding("CLAMAV", CRITICAL, "known_malware",
                            "ClamAV: " + line.rsplit(": ", 1)[-1].removesuffix(" FOUND"),
                            line.rsplit(": ", 1)[0], "clamav")
                    for line in p.stdout.splitlines() if line.endswith(" FOUND")]
    return None
