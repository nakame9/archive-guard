"""Giao diện dòng lệnh: archiveguard <file hoặc thư mục>…"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, isolate, malwarebazaar
from .extract import archive_kind
from .rules import CATEGORIES, SEVERITY_NAME
from .scanner import VERDICTS, Report, Scanner

LABEL = {"clean": "SẠCH", "incomplete": "CHƯA QUÉT ĐỦ", "suspicious": "ĐÁNG NGỜ", "malicious": "NGUY HIỂM"}
COLOR = {"clean": "32", "incomplete": "35", "suspicious": "33", "malicious": "31"}
# Tăng khi đổi tên/xóa/đổi nghĩa một trường JSON; chỉ THÊM trường mới thì giữ nguyên
SCHEMA_VERSION = 1
EXIT_CODE = {"clean": 0, "suspicious": 1, "malicious": 2, "incomplete": 4}


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
          f"{counts['suspicious']} đáng ngờ, {counts['incomplete']} chưa quét đủ, {counts['clean']} sạch")
    for note in report.incomplete:
        print(paint(f"  ! Chưa kiểm tra được: {note}", "33"))
    verdict = report.verdict
    kinds = ", ".join(CATEGORIES.get(c, c) for c in report.categories)
    partial = (f" (CHƯA ĐẦY ĐỦ – {len(report.incomplete)} phần chưa kiểm tra)"
               if report.incomplete and verdict != "incomplete" else "")
    print("  KẾT LUẬN: " + paint(LABEL[verdict] + partial, COLOR[verdict] + ";1")
          + (f" – dấu hiệu: {kinds}" if kinds else ""))
    if verdict == "incomplete":
        print("  (Phần đã quét không có dấu hiệu nguy hiểm, nhưng những phần ở trên CHƯA được kiểm tra –"
              " KHÔNG được coi là an toàn.)")
    elif verdict == "clean":
        print("  (Không phát hiện dấu hiệu nguy hiểm – không có nghĩa là chắc chắn an toàn.)")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="archiveguard",
        description="Quét file nén (ZIP, RAR, 7z, TAR, GZ…) tìm dấu hiệu trojan, keylogger, worm, ransomware…",
        epilog="Mã thoát: 0 = sạch, 1 = đáng ngờ, 2 = nguy hiểm, 3 = lỗi, 4 = chưa quét đủ (không được coi là sạch).")
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
    ap.add_argument("--max-total", type=int, default=4096, metavar="MB",
                    help="tổng dung lượng giải nén tối đa cho mỗi file nén, tính cả các tầng lồng nhau (mặc định 4096 MB)")
    ap.add_argument("--timeout", type=int, default=300, metavar="GIÂY",
                    help="thời gian quét tối đa cho mỗi file nén (mặc định 300 giây)")
    ap.add_argument("--isolate", action="store_true",
                    help="quét mỗi file nén trong một process con riêng: treo/crash/hết RAM không ảnh hưởng phần còn lại")
    ap.add_argument("--worker-timeout", type=float, metavar="GIÂY",
                    help="hard timeout của mỗi worker, quá hạn là kill cả cây process (mặc định --timeout + 30)")
    ap.add_argument("--worker-memory", type=int, metavar="MB",
                    help="giới hạn RAM cho worker và process con của nó (Linux, Windows; cần --isolate)")
    ap.add_argument("--_worker", action="store_true", help=argparse.SUPPRESS)  # process con của --isolate
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
    if (args.worker_timeout or args.worker_memory) and not args.isolate:
        ap.error("--worker-timeout và --worker-memory cần đi kèm --isolate")
    if args.worker_memory and not isolate.MEMORY_SUPPORTED:
        ap.error("--worker-memory chỉ hỗ trợ Linux và Windows")
    if args._worker:  # mật khẩu được truyền qua stdin để không lộ trên dòng lệnh
        args.password += json.load(sys.stdin).get("passwords", [])
    hard_timeout = args.worker_timeout or args.timeout + 30
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
                      max_total_mb=args.max_total, timeout=args.timeout,
                      hash_files=args.hashes, yara_paths=args.yara,
                      use_yara=not args.no_yara, use_clamav=not args.no_clamav)
    if not args._worker:
        print(f"ArchiveGuard {__version__} | luật {scanner.rules_version} | "
              + " | ".join(f"{k}: {v}" for k, v in scanner.engines.items())
              + (f" | cô lập: bật (timeout cứng {hard_timeout:g}s"
                 + (f", RAM {args.worker_memory} MB" if args.worker_memory else "") + ")" if args.isolate else ""))
    worker_args = ["--max-depth", str(args.max_depth), "--max-size", str(args.max_size),
                   "--max-total", str(args.max_total), "--timeout", str(args.timeout)]
    worker_args += [x for y in args.yara for x in ("--yara", str(y.resolve()))]
    worker_args += [x for h in args.hashes for x in ("--hashes", str(h.resolve()))]
    worker_args += [f for f, on in (("--all", args.all), ("--no-yara", args.no_yara),
                                    ("--no-clamav", args.no_clamav)) if on]

    reports, failed = [], False
    for path in _targets(args.paths):
        if args.isolate:
            report, output, error, timed_out = isolate.scan(path, worker_args, args.password,
                                                             hard_timeout, args.worker_memory)
            print(output, end="")
            if report is None:  # worker treo/crash/hết RAM: CHƯA QUÉT ĐỦ, không bao giờ là SẠCH
                failed_report = Report(str(path), incomplete=[error])
                _print_report(failed_report, args.all, paint)
                report = failed_report.to_dict() | {"worker_error": error}
                failed = failed or not timed_out  # crash/lỗi → mã 3; hết giờ → CHƯA QUÉT ĐỦ (mã 4)
            reports.append(report)
            continue
        try:
            report = scanner.scan_path(path)
        except OSError as e:
            print(f"\nLỗi: không đọc được {path}: {e.strerror or e}", file=sys.stderr)
            failed = True
            continue
        except Exception as e:  # lỗi ngoài dự kiến: báo lỗi (mã 3), tuyệt đối không để lọt thành "sạch"
            print(f"\nLỗi khi quét {path}: {type(e).__name__}: {e}", file=sys.stderr)
            failed = True
            continue
        reports.append(report.to_dict())
        _print_report(report, args.all, paint)

    if not reports and not failed and not args._worker:
        print("Không tìm thấy file nén nào để quét.")
    if args.json:
        args.json.write_text(json.dumps({"schema_version": SCHEMA_VERSION, "version": __version__,
                                         "rules_version": scanner.rules_version,
                                         "rules_components": scanner.rules_components,
                                         "engines": scanner.engines,
                                         "isolation": {"hard_timeout": hard_timeout,
                                                       "memory_mb": args.worker_memory} if args.isolate else None,
                                         "reports": reports},
                                        ensure_ascii=False, indent=2), encoding="utf-8")
        if not args._worker:
            print(f"\nĐã ghi báo cáo JSON: {args.json}")
    worst = max((r["verdict"] for r in reports), key=VERDICTS.index, default="clean")
    if failed and worst in ("clean", "incomplete"):
        return 3
    return EXIT_CODE[worst]
