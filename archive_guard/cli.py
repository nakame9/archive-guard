"""Giao diện dòng lệnh: archiveguard <file hoặc thư mục>…"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, malwarebazaar
from .extract import archive_kind
from .rules import CATEGORIES, SEVERITY_NAME
from .scanner import Scanner

LABEL = {"clean": "SẠCH", "suspicious": "ĐÁNG NGỜ", "malicious": "NGUY HIỂM"}
COLOR = {"clean": "32", "suspicious": "33", "malicious": "31"}
EXIT_CODE = {"clean": 0, "suspicious": 1, "malicious": 2}


def _targets(paths):
    """File được quét trực tiếp; thư mục thì quét mọi file nén bên trong (nhận diện theo nội dung)."""
    for p in paths:
        if not p.is_dir():
            yield p
            continue
        for f in sorted(p.rglob("*")):
            try:
                with f.open("rb") as fh:
                    is_archive = archive_kind(fh.read(512)) is not None
            except OSError:  # thư mục con, file bị khóa…
                continue
            if is_archive:
                yield f


def _print_report(report, show_all, paint):
    print(paint(f"\n== {report.target} ==", "1"))
    for f in report.files:
        if f.verdict == "clean" and not show_all:
            continue
        print(f"  {paint(f'[{LABEL[f.verdict]} {f.score}]', COLOR[f.verdict])} {f.path}"
              + (f"  ({f.note})" if f.note else ""))
        for x in sorted(f.findings, key=lambda x: -x.severity):
            cat = CATEGORIES.get(x.category, x.category)
            print(f"      {SEVERITY_NAME[x.severity]:<8} {cat}: {x.title}")
            if x.detail:
                print(f"               {x.detail}")
    counts = {v: sum(1 for f in report.files if f.verdict == v) for v in LABEL}
    print(f"  Đã quét {len(report.files)} file: {counts['malicious']} nguy hiểm, "
          f"{counts['suspicious']} đáng ngờ, {counts['clean']} sạch")
    for note in report.incomplete:
        print(paint(f"  ! Chưa kiểm tra được: {note}", "33"))
    verdict = report.verdict
    kinds = ", ".join(CATEGORIES.get(c, c) for c in report.categories)
    print("  KẾT LUẬN: " + paint(LABEL[verdict], COLOR[verdict] + ";1") + (f" – dấu hiệu: {kinds}" if kinds else ""))
    if verdict == "clean":
        print("  (Không phát hiện dấu hiệu nguy hiểm – không có nghĩa là chắc chắn an toàn.)")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="archiveguard",
        description="Quét file nén (ZIP, RAR, 7z, TAR, GZ…) tìm dấu hiệu trojan, keylogger, worm, ransomware…",
        epilog="Mã thoát: 0 = sạch, 1 = đáng ngờ, 2 = nguy hiểm, 3 = lỗi.")
    ap.add_argument("paths", nargs="*", type=Path, help="file hoặc thư mục (thư mục: quét mọi file nén bên trong)")
    ap.add_argument("--update-hashes", action="store_true",
                    help="tải/cập nhật mã băm mã độc theo họ từ MalwareBazaar vào cache trên máy")
    ap.add_argument("--auth-key", default=os.environ.get("ABUSECH_AUTH_KEY", ""), metavar="KEY",
                    help="Auth-Key miễn phí của abuse.ch (mặc định lấy từ biến môi trường ABUSECH_AUTH_KEY)")
    ap.add_argument("-p", "--password", action="append", default=[], help="mật khẩu thử cho file nén (lặp lại được)")
    ap.add_argument("--json", type=Path, metavar="FILE", help="ghi báo cáo chi tiết ra file JSON")
    ap.add_argument("-a", "--all", action="store_true", help="liệt kê cả những file sạch")
    ap.add_argument("--yara", action="append", default=[], type=Path, metavar="PATH",
                    help="thêm file/thư mục luật YARA (lặp lại được)")
    ap.add_argument("--hashes", action="append", default=[], type=Path, metavar="FILE",
                    help="thêm danh sách mã băm mã độc (lặp lại được)")
    ap.add_argument("--max-depth", type=int, default=5, help="số tầng file nén lồng nhau tối đa (mặc định 5)")
    ap.add_argument("--max-size", type=int, default=256, metavar="MB",
                    help="dung lượng tối đa của mỗi file được đọc (mặc định 256 MB)")
    ap.add_argument("--no-yara", action="store_true", help="không dùng YARA")
    ap.add_argument("--no-clamav", action="store_true", help="không dùng ClamAV")
    ap.add_argument("--no-color", action="store_true", help="tắt màu")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # cmd Windows + tiếng Việt
    color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    if color and os.name == "nt":
        os.system("")  # bật mã màu ANSI trên cmd Windows đời cũ
    paint = (lambda s, c: f"\033[{c}m{s}\033[0m") if color else (lambda s, c: s)

    if not args.paths and not args.update_hashes:
        ap.error("cần ít nhất một file/thư mục để quét, hoặc --update-hashes")
    for extra in args.yara + args.hashes:
        if not extra.exists():
            ap.error(f"không tìm thấy {extra}")
    if args.update_hashes:
        print(f"Cập nhật mã băm từ MalwareBazaar vào {malwarebazaar.cache_path()} …")
        try:
            added, total = malwarebazaar.update(args.auth_key)
        except (RuntimeError, OSError) as e:  # thiếu/sai Auth-Key, mất mạng…
            print(f"Lỗi cập nhật: {e}", file=sys.stderr)
            return 3
        print(f"Xong: thêm {added} mã băm mới, cache có {total} mẫu.")
        if not args.paths:
            return 0
    scanner = Scanner(passwords=args.password, max_depth=args.max_depth, max_file_mb=args.max_size,
                      hash_files=args.hashes, yara_paths=args.yara,
                      use_yara=not args.no_yara, use_clamav=not args.no_clamav)
    print(f"ArchiveGuard {__version__} | " + " | ".join(f"{k}: {v}" for k, v in scanner.engines.items()))

    reports, failed = [], False
    for path in _targets(args.paths):
        try:
            report = scanner.scan_path(path)
        except OSError as e:
            print(f"\nLỗi: không đọc được {path}: {e.strerror or e}", file=sys.stderr)
            failed = True
            continue
        reports.append(report)
        _print_report(report, args.all, paint)

    if not reports and not failed:
        print("Không tìm thấy file nén nào để quét.")
    if args.json:
        args.json.write_text(json.dumps({"version": __version__, "engines": scanner.engines,
                                         "reports": [r.to_dict() for r in reports]},
                                        ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nĐã ghi báo cáo JSON: {args.json}")
    code = max((EXIT_CODE[r.verdict] for r in reports), default=0)
    return 3 if failed and code == 0 else code
