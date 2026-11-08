"""Giao diện dòng lệnh: archiveguard <file hoặc thư mục>…"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10
    import tomli as tomllib

from . import __version__, engines, isolate, malwarebazaar, sandbox
from .extract import archive_kind, has_trailing_zip
from .rules import CATEGORIES, SEVERITY_NAME
from .scanner import VERDICTS, Report, Scanner

LABEL = {"clean": "SẠCH", "incomplete": "CHƯA QUÉT ĐỦ", "suspicious": "ĐÁNG NGỜ", "malicious": "NGUY HIỂM"}
COLOR = {"clean": "32", "incomplete": "35", "suspicious": "33", "malicious": "31"}
# Tăng khi đổi tên/xóa/đổi nghĩa một trường JSON; chỉ THÊM trường mới thì giữ nguyên
SCHEMA_VERSION = 1
EXIT_CODE = {"clean": 0, "suspicious": 1, "malicious": 2, "incomplete": 4}
FAILABLE = ("suspicious", "malicious", "incomplete")
CONFIG_ENV = "ARCHIVEGUARD_CONFIG"
ENV_PREFIX = "ARCHIVEGUARD_"
# Không đọc từ file cấu hình/biến môi trường: bí mật (mật khẩu có tùy chọn riêng; Auth-Key dùng ABUSECH_AUTH_KEY),
# hành động một lần, và tùy chọn nội bộ
_NOT_CONFIGURABLE = {"help", "version", "paths", "password", "auth_key", "update_hashes", "update_db", "config",
                     "_worker"}
VT_KINDS = {"pe", "elf", "macho", "script", "lnk", "ole", "pdf", "unknown"}  # loại file đáng tra VirusTotal


def _virustotal(report, api_key, state, paint):
    """Tra mã băm của file thực thi/script/tài liệu trong báo cáo (dict) trên VirusTotal; ≥ VT_MIN_ENGINES engine
    phát hiện → thêm phát hiện CRITICAL và nâng kết luận. VirusTotal lỗi/hết lượt không làm đổi kết luận."""
    for i, f in enumerate(report.get("files", [])):
        sha = f.get("sha256")
        if (not sha or state["left"] <= 0 or state["off"] or (i and f.get("kind") not in VT_KINDS)
                or any(x.get("engine") == "hash" for x in f.get("findings", []))):
            continue
        if sha not in state["seen"]:
            state["left"] -= 1
            try:
                state["seen"][sha] = engines.virustotal_lookup(sha, api_key)
            except (OSError, ValueError, KeyError) as e:
                print(paint(f"  ! VirusTotal không dùng được ({e}); bỏ qua phần còn lại", "33"))
                state["off"] = True
                return
        hit = state["seen"][sha]
        if hit and hit["malicious"] >= engines.VT_MIN_ENGINES:
            title = f"VirusTotal: {hit['malicious']}/{hit['total']} engine phát hiện là mã độc"
            print(paint(f"  VirusTotal: {_safe(f['path'])}: {hit['malicious']}/{hit['total']} engine", "31"))
            isolate.add_known_malware(report, i, [{
                "rule": "HASH.VIRUSTOTAL", "severity": "CRITICAL", "category": "known_malware", "title": title,
                "detail": sha, "engine": "virustotal", "confidence": "high", "attack": ""}])


def _fail_on(text):
    chosen = {x.strip() for x in text.split(",") if x.strip()}
    if not chosen or chosen - set(FAILABLE):
        raise argparse.ArgumentTypeError(f"chọn trong {', '.join(FAILABLE)} (phân cách bằng dấu phẩy)")
    return chosen


def _coerce(action, value, where, ap):
    """Giá trị từ TOML (đã có kiểu) hoặc biến môi trường (chuỗi) → đúng kiểu argparse dùng cho tùy chọn đó."""
    try:
        if action.nargs == 0:  # cờ bật/tắt
            if isinstance(value, bool):
                return value
            if str(value).lower() in ("1", "true", "yes", "on", "0", "false", "no", "off"):
                return str(value).lower() in ("1", "true", "yes", "on")
            raise ValueError("cần true/false")
        convert = action.type or str
        if isinstance(value, list) and not isinstance(action, argparse._AppendAction):
            value = ",".join(map(str, value))  # vd. fail-on = ["malicious", "incomplete"]
        if isinstance(action, argparse._AppendAction):  # danh sách: mảng TOML, hoặc phân cách bằng os.pathsep
            items = value if isinstance(value, list) else str(value).split(os.pathsep)
            return [convert(str(v)) for v in items if str(v)]
        return convert(value if isinstance(value, (int, float)) and convert in (int, float) else str(value))
    except (ValueError, TypeError, argparse.ArgumentTypeError) as e:
        ap.error(f"{where}: giá trị {value!r} không hợp lệ ({e})")


def _apply_config(ap, argv):
    """Mặc định lấy từ file TOML (--config hoặc ARCHIVEGUARD_CONFIG), rồi biến môi trường ARCHIVEGUARD_*;
    tham số dòng lệnh luôn thắng. Không tự tìm file cấu hình trong thư mục hiện tại: đó có thể chính là thư mục
    chứa file cần quét, kẻ tấn công không được phép cài cấu hình (vd. allowlist, tắt YARA) vào đó.
    """
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", type=Path)
    known, _ = pre.parse_known_args(argv)
    path = known.config or (Path(os.environ[CONFIG_ENV]) if os.environ.get(CONFIG_ENV) else None)
    values = {}
    if path:
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
            ap.error(f"không đọc được file cấu hình {path}: {e}")
        values = {k.replace("-", "_"): (v, f"{path}: {k}") for k, v in data.items()}
    values |= {k[len(ENV_PREFIX):].lower(): (v, k) for k, v in os.environ.items()
               if k.startswith(ENV_PREFIX) and k != CONFIG_ENV}
    actions = {a.dest: a for a in ap._actions if a.dest not in _NOT_CONFIGURABLE}
    defaults = {}
    for dest, (value, where) in values.items():
        if dest not in actions:
            ap.error(f"{where}: không có tùy chọn này (gõ nhầm?)")
        defaults[dest] = _coerce(actions[dest], value, where, ap)
    ap.set_defaults(**defaults)
    return path


def _write_stats(path, reports, errors, seconds, slowest, code, rules_version):
    """Số liệu dạng Prometheus (node_exporter textfile collector hoặc đẩy lên Pushgateway). Ghi file tạm rồi đổi tên:
    collector không bao giờ đọc phải file viết dở."""
    count = {v: sum(r["verdict"] == v for r in reports) for v in VERDICTS}
    lines = [
        "# HELP archiveguard_archives File nén đã quét trong lần chạy gần nhất, theo kết luận.",
        "# TYPE archiveguard_archives gauge",
        *(f'archiveguard_archives{{verdict="{v}"}} {n}' for v, n in count.items()),
        "# HELP archiveguard_files File đã kiểm tra (gồm cả file bên trong file nén).",
        "# TYPE archiveguard_files gauge",
        f"archiveguard_files {sum(len(r.get('files', [])) for r in reports)}",
        "# HELP archiveguard_errors File không quét được vì lỗi (đọc file, worker crash).",
        "# TYPE archiveguard_errors gauge",
        f"archiveguard_errors {errors}",
        "# HELP archiveguard_duration_seconds Tổng thời gian quét (chia cho số file nén để ra thời gian trung bình).",
        "# TYPE archiveguard_duration_seconds gauge",
        f"archiveguard_duration_seconds {seconds:.3f}",
        "# HELP archiveguard_archive_duration_max_seconds Thời gian quét file nén lâu nhất.",
        "# TYPE archiveguard_archive_duration_max_seconds gauge",
        f"archiveguard_archive_duration_max_seconds {slowest:.3f}",
        "# HELP archiveguard_exit_code Mã thoát của lần chạy (0 sạch, 1 đáng ngờ, 2 nguy hiểm, 3 lỗi, 4 chưa quét đủ).",
        "# TYPE archiveguard_exit_code gauge",
        f"archiveguard_exit_code {code}",
        "# HELP archiveguard_last_run_timestamp_seconds Thời điểm kết thúc lần chạy (Unix).",
        "# TYPE archiveguard_last_run_timestamp_seconds gauge",
        f"archiveguard_last_run_timestamp_seconds {time.time():.0f}",
        "# HELP archiveguard_info Phiên bản và bộ luật đang dùng.",
        "# TYPE archiveguard_info gauge",
        f'archiveguard_info{{version="{__version__}",rules_version="{rules_version}"}} 1',
    ]
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _targets(paths):
    """File được quét trực tiếp; thư mục thì quét mọi file nén bên trong (nhận diện theo nội dung)."""
    for p in paths:
        if not p.is_dir():
            yield p
            continue
        for f in sorted(p.rglob("*")):
            if not f.is_file():  # thư mục con, FIFO, thiết bị: open() trên FIFO chặn mãi
                continue
            try:
                with f.open("rb") as fh:
                    # bắt cả ZIP có byte rác ở đầu, SFX dạng ZIP (danh mục nằm ở cuối file)
                    is_archive = archive_kind(fh.read(512)) is not None or has_trailing_zip(fh)
            except OSError:  # file bị khóa…
                continue
            if is_archive:
                yield f


# Ký tự điều khiển terminal (ESC…) và ký tự đảo chiều Unicode trong tên file lấy từ file nén do kẻ tấn công đặt:
# in thô ra có thể đổi màu/xóa màn hình/giả mạo đuôi file trên terminal của người dùng
_UNSAFE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def _safe(text) -> str:
    return _UNSAFE.sub(lambda m: f"\\u{ord(m.group()):04x}", str(text))


def _print_report(report, show_all, paint):
    print(paint(f"\n== {_safe(report.target)} ==", "1"))
    for f in report.files:
        if f.verdict == "clean" and not show_all:
            continue
        print(f"  {paint(f'[{LABEL[f.verdict]} {f.score}]', COLOR[f.verdict])} {_safe(f.path)}"
              + (f"  ({_safe(f.note)})" if f.note else ""))
        for x in sorted(f.findings, key=lambda x: -x.severity):
            cat = CATEGORIES.get(x.category, x.category)
            tags = "".join([f" [{x.attack}]" if x.attack else "", " · khả năng" if x.confidence == "low" else ""])
            print(f"      {SEVERITY_NAME[x.severity]:<8} {cat}: {_safe(x.title)}{_safe(tags)}")
            if x.detail:
                print(f"               {_safe(x.detail)}")
    for f in report.files:
        if f.allowlisted and f.suppressed:
            print(paint(f"  Allowlist ({_safe(f.allowlisted)}): bỏ qua {len(f.suppressed)} phát hiện ở {_safe(f.path)}",
                        "2"))
    counts = {v: sum(1 for f in report.files if f.verdict == v) for v in LABEL}
    print(f"  Đã quét {len(report.files)} file: {counts['malicious']} nguy hiểm, "
          f"{counts['suspicious']} đáng ngờ, {counts['incomplete']} chưa quét đủ, {counts['clean']} sạch")
    for note in report.incomplete:
        print(paint(f"  ! Chưa kiểm tra được: {_safe(note)}", "33"))
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
        epilog="Mã thoát: 0 = sạch, 1 = đáng ngờ, 2 = nguy hiểm, 3 = lỗi, 4 = chưa quét đủ (không được coi là sạch). "
               "Mọi tùy chọn (trừ mật khẩu) đặt được trong file TOML (--config) hoặc biến môi trường "
               "ARCHIVEGUARD_<TÊN>, vd. ARCHIVEGUARD_TIMEOUT=600; dòng lệnh luôn thắng.")
    ap.add_argument("paths", nargs="*", type=Path, help="file hoặc thư mục (thư mục: quét mọi file nén bên trong)")
    ap.add_argument("--update-hashes", action="store_true",
                    help="tải/cập nhật mã băm mã độc theo họ từ MalwareBazaar vào cache trên máy")
    ap.add_argument("--update-db", action="store_true",
                    help="tải danh sách mã băm đã ký từ GitHub Release và xác minh chữ ký Sigstore "
                         "(không cần Auth-Key; cần pip install 'archive-guard[update]')")
    ap.add_argument("--auth-key", default=os.environ.get("ABUSECH_AUTH_KEY", ""), metavar="KEY",
                    help="Auth-Key miễn phí của abuse.ch (mặc định lấy từ biến môi trường ABUSECH_AUTH_KEY)")
    ap.add_argument("-p", "--password", action="append", default=[], help="mật khẩu thử cho file nén (lặp lại được)")
    ap.add_argument("--json", type=Path, metavar="FILE", help="ghi báo cáo chi tiết ra file JSON")
    ap.add_argument("--stats", type=Path, metavar="FILE",
                    help="ghi số liệu dạng Prometheus (số file, kết luận, lỗi, thời gian) cho Grafana/node_exporter")
    ap.add_argument("--config", type=Path, metavar="FILE",
                    help=f"file cấu hình TOML (hoặc biến môi trường {CONFIG_ENV}); xem docs/USAGE.md")
    ap.add_argument("--fail-on", type=_fail_on, default=set(FAILABLE), metavar="KẾT_LUẬN",
                    help="kết luận nào làm lệnh thất bại, vd. malicious hoặc malicious,incomplete "
                         "(mặc định: suspicious,malicious,incomplete); kết luận khác trả mã 0. Lỗi luôn là mã 3")
    ap.add_argument("--virustotal", action="store_true",
                    help="tra thêm MÃ BĂM (không gửi file) của file thực thi/script/tài liệu trên VirusTotal; "
                         "cần biến môi trường VT_API_KEY")
    ap.add_argument("--vt-limit", type=int, default=20, metavar="N",
                    help="số lượt tra VirusTotal tối đa mỗi lần chạy (mặc định 20; API miễn phí: 500 lượt/ngày)")
    ap.add_argument("--allowlist", action="append", default=[], type=Path, metavar="FILE",
                    help="bỏ qua phát hiện cho file đã kiểm duyệt: dòng `sha256:<mã>` hoặc `path:<glob>` "
                         "(đường dẫn trên đĩa); không bao giờ che mã độc đã biết (lặp lại được)")
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
    ap.add_argument("--max-archive-size", type=int, default=4096, metavar="MB",
                    help="kích thước tối đa của file nén đầu vào (mặc định 4096 MB); lớn hơn là CHƯA QUÉT ĐỦ")
    ap.add_argument("--timeout", type=int, default=300, metavar="GIÂY",
                    help="thời gian quét tối đa cho mỗi file nén (mặc định 300 giây)")
    ap.add_argument("--isolate", action="store_true",
                    help="(mặc định, giữ để tương thích) quét mỗi file nén trong một worker có sandbox")
    ap.add_argument("--no-isolate", action="store_true",
                    help="KHÔNG khuyến khích với dữ liệu không tin cậy: chạy parser ngay trong process chính, không sandbox")
    ap.add_argument("--no-sandbox", action="store_true",
                    help="vẫn dùng worker nhưng không áp sandbox hệ điều hành (khi sandbox làm hỏng môi trường lạ)")
    ap.add_argument("--require-sandbox", action="store_true",
                    help="báo lỗi thay vì quét nếu worker không giới hạn được truy cập file và chặn được mạng")
    ap.add_argument("--worker-timeout", type=float, metavar="GIÂY",
                    help="hard timeout của mỗi worker, quá hạn là kill cả cây process (mặc định --timeout + 30)")
    ap.add_argument("--worker-memory", type=int, metavar="MB",
                    help="giới hạn RAM cho worker và process con của nó (Linux, Windows)")
    ap.add_argument("--_worker", action="store_true", help=argparse.SUPPRESS)  # process con của chế độ cô lập
    ap.add_argument("--no-yara", action="store_true", help="không dùng YARA")
    ap.add_argument("--no-clamav", action="store_true", help="không dùng ClamAV")
    ap.add_argument("--no-color", action="store_true", help="tắt màu")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    config_path = _apply_config(ap, argv)
    args = ap.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # cmd Windows + tiếng Việt
    color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    if color and os.name == "nt":
        os.system("")  # bật mã màu ANSI trên cmd Windows đời cũ
    paint = (lambda s, c: f"\033[{c}m{s}\033[0m") if color else (lambda s, c: s)

    if not args.paths and not args.update_hashes and not args.update_db:
        ap.error("cần ít nhất một file/thư mục để quét, hoặc --update-hashes / --update-db")
    if args.no_isolate and (args.isolate or args.worker_timeout or args.worker_memory or args.no_sandbox
                            or args.require_sandbox):
        ap.error("--no-isolate không dùng chung được với --isolate/--worker-*/--no-sandbox/--require-sandbox")
    if args.no_sandbox and args.require_sandbox:
        ap.error("--no-sandbox và --require-sandbox mâu thuẫn nhau")
    if args.worker_memory and not isolate.MEMORY_SUPPORTED:
        ap.error("--worker-memory chỉ hỗ trợ Linux và Windows")
    use_worker = not args.no_isolate and not args._worker
    request = {}
    if args._worker:  # mật khẩu và yêu cầu sandbox được truyền qua stdin, không lộ trên dòng lệnh
        request = json.load(sys.stdin)
        args.password += request.get("passwords", [])
    hard_timeout = args.worker_timeout or args.timeout + 30
    for extra in args.yara + args.hashes + args.allowlist:
        if not extra.exists():
            ap.error(f"không tìm thấy {extra}")
    vt_key = os.environ.get("VT_API_KEY", "")
    if args.virustotal and not vt_key:
        ap.error("--virustotal cần biến môi trường VT_API_KEY (khóa API miễn phí tại virustotal.com)")
    vt_state = {"left": args.vt_limit, "seen": {}, "off": False}
    if args.update_db:
        print(f"Tải danh sách mã băm đã ký từ {malwarebazaar.DB_URL} …")
        try:
            total = malwarebazaar.download_db()
        except (RuntimeError, OSError) as e:  # chữ ký sai, thiếu thư viện sigstore, mất mạng…
            print(f"Lỗi cập nhật: {e}", file=sys.stderr)
            return 3
        print(f"Xong: chữ ký hợp lệ, cache {malwarebazaar.cache_path()} có {total} mã băm.")
        if not args.paths and not args.update_hashes:
            return 0
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
    try:
        scanner = Scanner(passwords=args.password, max_depth=args.max_depth, max_file_mb=args.max_size,
                          max_total_mb=args.max_total, timeout=args.timeout, max_archive_mb=args.max_archive_size,
                          hash_files=args.hashes, yara_paths=args.yara, allowlist=args.allowlist,
                          use_yara=not args.no_yara, use_clamav=not args.no_clamav)
    except ValueError as e:  # allowlist sai định dạng: dừng hẳn, không quét với allowlist thiếu dòng
        ap.error(str(e))
    if args._worker and not args.no_clamav:  # worker không mở được socket tới clamd
        if request.get("clamd_done"):  # process cha đã quét bằng clamdscan và TỰ gộp kết quả (worker không xóa được)
            scanner.use_clamav = True
            scanner.clamav = lambda path, timeout: []
        else:
            scanner.clamav = lambda path, timeout: engines.clamav_scan(path, timeout, commands=("clamscan",))
    sandbox_status = None
    if request.get("sandbox"):  # áp SAU khi nạp bộ luật (tin cậy), TRƯỚC khi đọc byte nào của file cần quét
        sandbox_status = sandbox.apply([p.resolve() for p in args.paths], os.environ.get("TMPDIR") or os.getcwd(),
                                       outer=request.get("outer"))
        lacking = sandbox.missing(sandbox_status)
        if request.get("require_sandbox") and lacking:
            print(f"Lỗi: --require-sandbox nhưng worker thiếu: {', '.join(lacking)} ({sandbox_status})",
                  file=sys.stderr)
            return 3
    if not args._worker:
        print(f"ArchiveGuard {__version__} | luật {scanner.rules_version} | "
              + " | ".join(f"{k}: {v}" for k, v in scanner.engines.items())
              + (f" | cô lập: bật (timeout cứng {hard_timeout:g}s"
                 + (f", RAM {args.worker_memory} MB" if args.worker_memory else "")
                 + (", không sandbox" if args.no_sandbox else ", sandbox") + ")"
                 if use_worker else " | cô lập: TẮT (parser chạy trong process chính)")
              + (f" | cấu hình: {config_path}" if config_path else "")
              + (f" | allowlist: {len(scanner.allowlist)} mục" if scanner.allowlist else ""))
    worker_args = ["--max-depth", str(args.max_depth), "--max-size", str(args.max_size),
                   "--max-total", str(args.max_total), "--timeout", str(args.timeout),
                   "--max-archive-size", str(args.max_archive_size)]
    worker_args += [x for y in args.yara for x in ("--yara", str(y.resolve()))]
    worker_args += [x for h in args.hashes for x in ("--hashes", str(h.resolve()))]
    worker_args += [x for a in args.allowlist for x in ("--allowlist", str(a.resolve()))]
    worker_args += [f for f, on in (("--all", args.all), ("--no-yara", args.no_yara),
                                    ("--no-clamav", args.no_clamav)) if on]

    reports, failed, errors, worker_sandbox = [], False, 0, None
    started, slowest = time.monotonic(), 0.0
    for path in _targets(args.paths):
        t0 = time.monotonic()
        if use_worker:
            # clamdscan --fdpass chạy ở đây: process cha chỉ chuyển file descriptor cho clamd, không phân tích file
            clamd = None if args.no_clamav else engines.clamav_scan(path, args.timeout, commands=("clamdscan",))
            report, output, error, timed_out = isolate.scan(path, worker_args, args.password, hard_timeout,
                                                             args.worker_memory, use_sandbox=not args.no_sandbox,
                                                             require_sandbox=args.require_sandbox, clamd=clamd)
            # worker có thể đã bị khai thác: không cho in ký tự điều khiển terminal (\r\n của Windows là bình thường)
            print(_safe(output.replace("\r\n", "\n")), end="")
            if report is not None and (not isinstance(report, dict) or report.get("verdict") not in VERDICTS):
                report, error, timed_out = None, "worker trả về kết quả không hợp lệ", False
            if report is not None:
                worker_sandbox = worker_sandbox or report.get("sandbox")
            if report is None:  # worker treo/crash/hết RAM: CHƯA QUÉT ĐỦ, không bao giờ là SẠCH
                failed_report = Report(str(path), incomplete=[error])
                _print_report(failed_report, args.all, paint)
                report = failed_report.to_dict() | {"worker_error": error}
                failed = failed or not timed_out  # crash/lỗi → mã 3; hết giờ → CHƯA QUÉT ĐỦ (mã 4)
                errors += not timed_out
            if args.virustotal:
                _virustotal(report, vt_key, vt_state, paint)
            reports.append(report)
            slowest = max(slowest, time.monotonic() - t0)
            continue
        try:
            report = scanner.scan_path(path)
        except OSError as e:
            print(f"\nLỗi: không đọc được {path}: {e.strerror or e}", file=sys.stderr)
            failed, errors = True, errors + 1
            continue
        except Exception as e:  # lỗi ngoài dự kiến: báo lỗi (mã 3), tuyệt đối không để lọt thành "sạch"
            print(f"\nLỗi khi quét {path}: {type(e).__name__}: {e}", file=sys.stderr)
            failed, errors = True, errors + 1
            continue
        reports.append(report.to_dict())
        _print_report(report, args.all, paint)
        if args.virustotal and not args._worker:
            _virustotal(reports[-1], vt_key, vt_state, paint)
        slowest = max(slowest, time.monotonic() - t0)

    if not reports and not failed and not args._worker:
        print("Không tìm thấy file nén nào để quét.")
    if worker_sandbox:
        layers = {k: v for k, v in worker_sandbox.items() if isinstance(v, str)}
        print(paint("\nSandbox của worker: " + "; ".join(f"{k}: {v}" for k, v in layers.items()), "2"))
    if args.json:
        args.json.write_text(json.dumps({"schema_version": SCHEMA_VERSION, "version": __version__,
                                         "rules_version": scanner.rules_version,
                                         "rules_components": scanner.rules_components,
                                         "engines": scanner.engines,
                                         "isolation": {"hard_timeout": hard_timeout, "memory_mb": args.worker_memory,
                                                       "sandbox": not args.no_sandbox} if use_worker else None,
                                         "sandbox": sandbox_status,
                                         "reports": reports},
                                        ensure_ascii=False, indent=2), encoding="utf-8")
        if not args._worker:
            print(f"\nĐã ghi báo cáo JSON: {args.json}")
    # --fail-on: chỉ những kết luận được chọn mới làm lệnh thất bại; lỗi (mã 3) thì luôn thất bại
    worst = max((r["verdict"] for r in reports if r["verdict"] in args.fail_on), key=VERDICTS.index, default="clean")
    code = 3 if failed and worst in ("clean", "incomplete") else EXIT_CODE[worst]
    if args.stats and not args._worker:
        _write_stats(args.stats, reports, errors, time.monotonic() - started, slowest, code, scanner.rules_version)
    return code
