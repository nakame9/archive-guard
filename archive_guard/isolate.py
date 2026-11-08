"""Chế độ cô lập (mặc định): mỗi file nén được quét trong một process con (worker) riêng.

Process cha chỉ khởi chạy worker, canh giờ, đọc file JSON kết quả và dọn dẹp. Worker bị treo, crash hay hết
RAM không làm hỏng cả lần quét: file đó nhận kết luận CHƯA QUÉT ĐỦ hoặc lỗi, KHÔNG BAO GIỜ là SẠCH.

Worker chính là lệnh `python -m archive_guard <file> --json …`; mật khẩu truyền qua stdin để không lộ trên
dòng lệnh (danh sách process). Đảm bảo theo hệ điều hành:
- hard timeout + dọn cả cây process con (vd. clamscan, unrar): Linux, macOS, Windows
- giới hạn RAM (--worker-memory) cho worker và process con của nó: Linux (RLIMIT_AS), Windows (Job Object).
  macOS không áp được RLIMIT_AS một cách tin cậy nên không hỗ trợ.

Worker còn tự áp sandbox hệ điều hành trước khi đọc dữ liệu (Landlock/seccomp/network namespace trên Linux,
sandbox-exec trên macOS) – xem sandbox.py. Giới hạn CPU = hard timeout trên mọi hệ điều hành.
"""
from __future__ import annotations

import json
import math
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

from . import malwarebazaar, sandbox
from .scanner import VERDICTS

MEMORY_SUPPORTED = sys.platform.startswith("linux") or os.name == "nt"
PACKAGE_PARENT = Path(__file__).resolve().parent.parent


def run(cmd, stdin: bytes, timeout: float, memory_mb: int | None = None, cwd=None, env=None):
    """Chạy cmd, trả (mã thoát, stdout, stderr, hết_giờ). Luôn dọn cả cây process con, kể cả khi lỗi.

    Giới hạn CPU = timeout (đề phòng worker dùng nhiều luồng đốt CPU nhanh hơn đồng hồ thật).
    """
    kw = {}
    cpu = max(1, math.ceil(timeout))
    if os.name == "posix":
        import resource

        def limits():
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
            if memory_mb:
                resource.setrlimit(resource.RLIMIT_AS, (memory_mb << 20, memory_mb << 20))

        kw["start_new_session"] = True  # process group riêng → kill được cả cây
        kw["preexec_fn"] = limits
    # stdout/stderr ghi ra file, KHÔNG qua pipe: process cháu tự tách khỏi nhóm (setsid) mà giữ đầu ghi của pipe thì
    # communicate() chờ EOF mãi mãi, vô hiệu hóa hard timeout. Với file, chỉ cần chờ chính worker thoát.
    # ponytail: process cháu đã setsid thoát được killpg và vẫn sống tới khi tự thoát (vẫn trong sandbox);
    # muốn dọn chắc chắn trên Linux thì đặt worker vào cgroup riêng
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=out, stderr=err, cwd=cwd, env=env, **kw)
        job = None
        try:
            if os.name == "nt":
                job = _windows_job(p, memory_mb, cpu)
            p.communicate(stdin, timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_tree(p, job)
            p.wait()
        finally:
            _kill_tree(p, job)  # dọn process cháu còn sót, vd. clamscan khi worker crash giữa chừng
            if job:
                _k32().CloseHandle(job)
        out.seek(0)
        err.seek(0)
        return p.returncode, out.read().decode("utf-8", "replace"), err.read().decode("utf-8", "replace"), timed_out


def _kill_tree(p, job):
    if os.name == "posix":
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass  # cả nhóm đã thoát
    elif job:
        _k32().TerminateJobObject(job, 1)
    elif p.poll() is None:
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
    if p.poll() is None:
        p.kill()


def _k32():
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    return k32


def _windows_job(p, memory_mb, cpu_seconds):
    """Gắn worker vào một Job Object: đóng job là kill cả cây; giới hạn thời gian CPU và (tùy chọn) RAM."""
    import ctypes
    from ctypes import wintypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in ("Read", "Write", "Other", "ReadT", "WriteT", "OtherT")]

    class BASIC(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class EXTENDED(ctypes.Structure):
        _fields_ = [("Basic", BASIC), ("Io", IO_COUNTERS), ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    k32 = _k32()
    job = k32.CreateJobObjectW(None, None)
    info = EXTENDED()
    info.Basic.LimitFlags = 0x2000 | 0x4  # KILL_ON_JOB_CLOSE | JOB_TIME (thời gian CPU của cả job)
    info.Basic.PerJobUserTimeLimit = cpu_seconds * 10_000_000  # đơn vị 100 ns
    if memory_mb:
        info.Basic.LimitFlags |= 0x200  # JOB_OBJECT_LIMIT_JOB_MEMORY: tính cả process con
        info.JobMemoryLimit = memory_mb << 20
    ok = job and k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))  # 9 = Extended
    # shortcut: worker chạy vài mili giây trước khi được gắn vào job; nó chỉ sinh process con (clamscan, unrar)
    # muộn hơn nhiều nên không lọt. Muốn chặt tuyệt đối thì tạo process ở trạng thái CREATE_SUSPENDED.
    ok = ok and k32.AssignProcessToJobObject(job, int(p._handle))
    if not ok:
        err = ctypes.get_last_error()
        if job:
            k32.CloseHandle(job)
        if memory_mb:  # người dùng yêu cầu giới hạn RAM mà không áp được → không chạy tiếp (fail safe)
            p.kill()
            raise OSError(f"không tạo được Job Object để giới hạn RAM (WinError {err})")
        return None  # vẫn kill được cây bằng taskkill
    return job


def worker_env(tmp) -> dict:
    """Biến môi trường tối thiểu cho worker: không lộ khóa API, token, HOME… cho code xử lý dữ liệu không tin cậy."""
    env = {k: v for k, v in os.environ.items()
           if k in ("PATH", "LANG", "SYSTEMROOT") or k.startswith(("LC_", "TMP", "PYTHON"))}
    cwd = os.getcwd()
    env.update({
        "TMP": tmp, "TEMP": tmp, "TMPDIR": tmp, "PYTHONIOENCODING": "utf-8",
        "PYTHONDONTWRITEBYTECODE": "1",  # worker không ghi .pyc (sandbox cũng không cho ghi ngoài tmp)
        # đường dẫn import của process cha (gồm cả site-packages của user, vốn cần HOME/APPDATA để tìm),
        # trừ thư mục hiện tại: file .py lạ ở đó (vd. Downloads) không được che thư viện
        "PYTHONPATH": os.pathsep.join(dict.fromkeys(
            [str(PACKAGE_PARENT), *(p for p in sys.path if p and os.path.abspath(p) != cwd)])),
        # cache mã băm cùng chỗ với process cha mà không cần HOME (cache_path() đọc LOCALAPPDATA trước)
        "LOCALAPPDATA": str(malwarebazaar.cache_path().parents[1]),
    })
    return env


def check_report(report) -> None:
    """Kiểm tra cấu trúc và tính nhất quán tối thiểu của báo cáo do worker trả về; sai thì ném ValueError.

    Chặn được báo cáo cụt, sai kiểu, tự mâu thuẫn (worker lỗi hoặc ghi dở). KHÔNG chặn được worker đã bị khai thác
    và nói dối khéo – xem docs/THREAT_MODEL.md.
    """
    if not isinstance(report, dict) or report.get("verdict") not in VERDICTS:
        raise ValueError("thiếu hoặc sai trường verdict")
    files, incomplete = report.get("files"), report.get("incomplete")
    if not isinstance(files, list) or not files or not all(isinstance(f, dict) for f in files):
        raise ValueError("trường files phải là danh sách khác rỗng")
    if not isinstance(incomplete, list):
        raise ValueError("thiếu hoặc sai trường incomplete")
    if incomplete and report["verdict"] == "clean":
        raise ValueError("mâu thuẫn: còn phần chưa quét nhưng kết luận SẠCH")


def add_known_malware(report: dict, index: int, findings: list) -> None:
    """Gộp phát hiện CRITICAL "mã độc đã biết" do process cha tự thu thập (ClamAV, VirusTotal) vào báo cáo dạng dict
    của file thứ index, và nâng kết luận lên NGUY HIỂM."""
    if not findings:
        return
    f = report["files"][index]
    f["findings"] += findings
    f["verdict"], f["score"] = "malicious", 100
    report["verdict"] = "malicious"
    report["categories"] = sorted({*report.get("categories", []), "known_malware"})


def scan(path, worker_args, passwords, hard_timeout: float, memory_mb: int | None = None,
         use_sandbox: bool = True, require_sandbox: bool = False, clamd=None, debug: bool = False):
    """Quét một file trong worker. Trả (report dict hoặc None, stdout của worker, lỗi hoặc None, hết_giờ).

    clamd: kết quả clamdscan do process cha chạy (list Finding), gộp vào báo cáo SAU khi worker trả về; None = worker
    tự chạy clamscan nếu có.
    report có thêm trường "sandbox": trạng thái các lớp sandbox mà worker đã áp (sandbox.py).
    """
    with tempfile.TemporaryDirectory(prefix="archiveguard-", ignore_cleanup_errors=True) as tmp:
        out = Path(tmp) / "report.json"
        env = worker_env(tmp)
        # cwd = thư mục tạm rỗng: `python -m` thêm cwd vào sys.path, không để file .py lạ ở thư mục người dùng
        # (vd. Downloads) che mất thư viện chuẩn
        cmd = [sys.executable, "-m", "archive_guard", str(Path(path).resolve()), "--_worker",
               "--json", str(out), *worker_args]
        wrapped = False
        if use_sandbox:
            cmd, wrapped = sandbox.macos_wrap(cmd, tmp)
        request = json.dumps({"passwords": list(passwords), "sandbox": use_sandbox, "require_sandbox": require_sandbox,
                              "outer": "sandbox-exec" if wrapped else None,
                              "clamd_done": clamd is not None}).encode()
        try:
            code, stdout, stderr, timed_out = run(cmd, request, hard_timeout, memory_mb, cwd=tmp, env=env)
        except OSError as e:
            return None, "", f"không khởi chạy được worker: {e}", False
        if timed_out:
            return None, stdout, f"worker bị dừng sau {hard_timeout:g} giây (hard timeout)", True
        try:
            data = json.loads(out.read_text(encoding="utf-8"))
            (report,) = data["reports"]  # đúng một báo cáo cho đúng một file
        except (OSError, ValueError, KeyError, TypeError):
            lines = stderr.strip().splitlines() or ["không có thông báo lỗi"]
            last = "\n".join(lines[-200:]) if debug else lines[-1]  # --debug: cả traceback, không chỉ dòng cuối
            return None, stdout, f"worker lỗi (mã thoát {code}): {last}", False
        try:
            check_report(report)
            report["sandbox"] = data.get("sandbox")
            # gộp ở ĐÂY, không gửi vào worker: worker bị khai thác có thể xóa phát hiện của ClamAV khỏi báo cáo
            add_known_malware(report, 0, [f.to_dict() for f in clamd or []])
        except (ValueError, KeyError, TypeError, IndexError) as e:
            return None, stdout, f"worker trả kết quả không hợp lệ: {e}", False
        return report, stdout, None, False
