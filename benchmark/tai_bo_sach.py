"""Tải lại bộ phần mềm sạch dùng để đo báo nhầm, kiểm tra SHA-256 từng file.

    python benchmark/tai_bo_sach.py benchmark/benign-corpus.txt phan_mem_sach/
    python -m archive_guard.benchmark --benign phan_mem_sach/ --no-clamav --out ketqua

Mỗi dòng manifest: `nhóm  tên_file  sha256  nguồn` với nguồn là `pypi:tên==phiên_bản` hoặc `npm:tên@phiên_bản`.
File đã có và đúng mã băm thì bỏ qua; file tải về sai mã băm bị xóa và báo lỗi (mã thoát 1).
Đây đều là phần mềm sạch, công khai – không có mã độc nào ở đây.
"""
from __future__ import annotations

import hashlib
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "archive-guard-benchmark"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return r.read()


def file_url(fname: str, source: str) -> str:
    kind, _, spec = source.partition(":")
    if kind == "pypi":
        name, _, version = spec.partition("==")
        info = json.loads(_get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json"))
        return next(u["url"] for u in info["urls"] if u["filename"] == fname)
    if kind == "npm":
        name, _, version = spec.rpartition("@")  # @scope/tên@phiên_bản
        info = json.loads(_get(f"https://registry.npmjs.org/{name.replace('/', '%2F')}/{urllib.parse.quote(version)}"))
        return info["dist"]["tarball"]
    raise ValueError(f"nguồn không hỗ trợ: {source}")


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 2:
        print(__doc__)
        return 2
    manifest, out = Path(argv[0]), Path(argv[1])
    entries = [line.split() for line in manifest.read_text(encoding="utf-8").splitlines()
               if line.strip() and not line.startswith("#")]
    bad = 0
    for i, (group, fname, sha256, source) in enumerate(entries, 1):
        dest = out / group / fname
        if dest.exists() and hashlib.sha256(dest.read_bytes()).hexdigest() == sha256:
            continue
        try:
            data = _get(file_url(fname, source))
        except Exception as e:  # một gói lỗi không dừng cả lượt
            print(f"  ! [{i}/{len(entries)}] {fname}: {e}", file=sys.stderr)
            bad += 1
            continue
        if hashlib.sha256(data).hexdigest() != sha256:
            print(f"  ! [{i}/{len(entries)}] {fname}: SHA-256 KHÔNG khớp manifest – bỏ", file=sys.stderr)
            bad += 1
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        print(f"  [{i}/{len(entries)}] {group}/{fname}")
    print(f"Xong: {len(entries) - bad}/{len(entries)} file đúng mã băm trong {out}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
