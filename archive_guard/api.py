"""API thư viện: quét file từ code Python (backend nhận upload, pipeline), LUÔN trong worker có sandbox.

    from archive_guard import scan_file

    result = scan_file("/srv/quarantine/abc123", require_sandbox=True)
    if result["disposition"] != "allow":
        ...  # review / quarantine / reject

Đọc hợp đồng tích hợp trước khi dùng cho dữ liệu không tin cậy: docs/INTEGRATION.md#tích-hợp-vào-backend
(quét bản trong vùng cách ly, xử lý ĐÚNG bản đó, không bao giờ nhận CHƯA QUÉT ĐỦ). Mẫu chạy được:
examples/upload_gate.py.
"""
import hashlib
import json
from pathlib import Path

from . import engines, isolate
from .scanner import Report

FAILABLE = ("suspicious", "malicious", "incomplete")
_ACTION = {"incomplete": "review", "suspicious": "quarantine", "malicious": "reject"}


def disposition(verdict: str, fail_on=FAILABLE) -> str:
    """Hành động gợi ý: allow | review | quarantine | reject.

    allow = "được chấp nhận theo policy hiện tại" (kết luận không nằm trong fail_on), KHÔNG phải bảo đảm an toàn.
    """
    return _ACTION[verdict] if verdict in fail_on else "allow"


def policy(settings: dict) -> dict:
    """Dấu vân tay của cấu hình hiệu lực: mã 12 ký tự tự sinh (như rules_version), không phải đặt tên bằng tay.

    File YARA / mã băm / allowlist thêm vào được tính theo NỘI DUNG, không theo đường dẫn: cùng policy trên hai máy
    thì cùng mã.
    """
    shown = {k: sorted(hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in v)
             if k in ("yara", "hashes", "allowlist") else sorted(v) if k == "fail_on" else v
             for k, v in settings.items()}
    return {"id": hashlib.sha256(json.dumps(shown, sort_keys=True).encode()).hexdigest()[:12], "settings": shown}


def worker_args(*, max_depth=5, max_size=256, max_total=4096, timeout=300, max_archive_size=4096,
                yara=(), hashes=(), allowlist=(), use_yara=True, use_clamav=True, show_all=False) -> list:
    """Tham số dòng lệnh cho worker (đường dẫn tuyệt đối: worker chạy trong thư mục tạm)."""
    args = ["--max-depth", str(max_depth), "--max-size", str(max_size), "--max-total", str(max_total),
            "--timeout", str(timeout), "--max-archive-size", str(max_archive_size)]
    args += [x for y in yara for x in ("--yara", str(Path(y).resolve()))]
    args += [x for h in hashes for x in ("--hashes", str(Path(h).resolve()))]
    args += [x for a in allowlist for x in ("--allowlist", str(Path(a).resolve()))]
    return args + [f for f, on in (("--all", show_all), ("--no-yara", not use_yara),
                                   ("--no-clamav", not use_clamav)) if on]


def scan_isolated(path, args, passwords, hard_timeout, memory_mb=None, *, sandbox=True, require_sandbox=False,
                  use_clamav=True, clamav_timeout=300):
    """Quét một file trong worker. LUÔN trả báo cáo: worker lỗi, treo, trả kết quả không hợp lệ → CHƯA QUÉT ĐỦ.

    Trả (báo cáo dict, output của worker, Report lỗi hoặc None, có phải hết giờ không). Dùng chung cho CLI và
    scan_file, để hai đường không lệch nhau.
    """
    # clamdscan --fdpass chạy ở process chính: chỉ chuyển file descriptor cho clamd, không phân tích file
    clamd = engines.clamav_scan(path, clamav_timeout, commands=("clamdscan",)) if use_clamav else None
    report, output, error, timed_out = isolate.scan(path, args, passwords, hard_timeout, memory_mb,
                                                     use_sandbox=sandbox, require_sandbox=require_sandbox, clamd=clamd)
    if report is not None:  # isolate.scan đã kiểm tra; kiểm lại để MỌI nguồn báo cáo đi qua cùng một cổng
        try:
            isolate.check_report(report)
        except ValueError as e:
            report, error, timed_out = None, f"worker trả kết quả không hợp lệ: {e}", False
    if report is not None:
        return report, output, None, False
    failure = Report(str(path))
    failure.skip("WORKER_TIMEOUT" if timed_out else "WORKER_ERROR", str(path), error)
    return failure.to_dict() | {"worker_error": error}, output, failure, timed_out


def scan_file(path, *, passwords=(), fail_on=FAILABLE, require_sandbox=False, worker_timeout=None,
              worker_memory=None, use_clamav=True, use_yara=True, max_depth=5, max_size=256, max_total=4096,
              timeout=300, max_archive_size=4096, yara=(), hashes=(), allowlist=()) -> dict:
    """Quét một file trong worker có sandbox; không có cách tắt cô lập qua API.

    Trả báo cáo như một phần tử `reports` của JSON (`--json`), thêm `disposition` và `policy`. Kích thước tính bằng
    MB, thời gian bằng giây, ý nghĩa như tùy chọn dòng lệnh cùng tên. require_sandbox=True: báo CHƯA QUÉT ĐỦ
    (`WORKER_ERROR`) thay vì quét khi worker không giới hạn được truy cập file và chặn mạng (hiện chỉ Linux x86_64).
    """
    path = Path(path)
    if not path.is_file():  # thư mục, FIFO, thiết bị: không mở (open() trên FIFO chặn mãi)
        raise FileNotFoundError(f"không phải file thường: {path}")
    if not set(fail_on) <= set(FAILABLE):
        raise ValueError(f"fail_on chỉ gồm {', '.join(FAILABLE)}")
    limits = {"max_depth": max_depth, "max_size": max_size, "max_total": max_total, "timeout": timeout,
              "max_archive_size": max_archive_size}
    args = worker_args(**limits, yara=yara, hashes=hashes, allowlist=allowlist, use_yara=use_yara,
                       use_clamav=use_clamav)
    report = scan_isolated(path, args, passwords, worker_timeout or timeout + 30, worker_memory,
                           require_sandbox=require_sandbox, use_clamav=use_clamav, clamav_timeout=timeout)[0]
    settings = limits | {"fail_on": fail_on, "require_sandbox": require_sandbox, "sandbox": True, "isolate": True,
                         "clamav": use_clamav, "yara_enabled": use_yara, "yara": yara, "hashes": hashes,
                         "allowlist": allowlist}
    return report | {"disposition": disposition(report["verdict"], fail_on), "policy": policy(settings)}
