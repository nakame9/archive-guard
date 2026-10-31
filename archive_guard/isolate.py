"""--isolate: mỗi file nén được quét trong một process con (worker) riêng.

Process cha chỉ khởi chạy worker, canh giờ, đọc file JSON kết quả và dọn dẹp. Worker bị treo, crash hay hết
RAM không làm hỏng cả lần quét: file đó nhận kết luận CHƯA QUÉT ĐỦ hoặc lỗi, KHÔNG BAO GIỜ là SẠCH.

Worker chính là lệnh `python -m archive_guard <file> --json …`; mật khẩu truyền qua stdin để không lộ trên
dòng lệnh (danh sách process). Đảm bảo theo hệ điều hành:
- hard timeout + dọn cả cây process con (vd. clamscan, unrar): Linux, macOS, Windows
- giới hạn RAM (--worker-memory) cho worker và process con của nó: Linux (RLIMIT_AS), Windows (Job Object).
  macOS không áp được RLIMIT_AS một cách tin cậy nên không hỗ trợ.

Đây là cô lập để ỔN ĐỊNH (treo/crash/hết RAM), không phải sandbox bảo mật: worker chạy cùng quyền người dùng.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

MEMORY_SUPPORTED = sys.platform.startswith("linux") or os.name == "nt"
PACKAGE_PARENT = Path(__file__).resolve().parent.parent


def run(cmd, stdin: bytes, timeout: float, memory_mb: int | None = None, cwd=None, env=None):
    """Chạy cmd, trả (mã thoát, stdout, stderr, hết_giờ). Luôn dọn cả cây process con, kể cả khi lỗi."""
    kw = {}
    if os.name == "posix":
        kw["start_new_session"] = True  # process group riêng → kill được cả cây
        if memory_mb:
            import resource
            limit = memory_mb << 20
            kw["preexec_fn"] = lambda: resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         cwd=cwd, env=env, **kw)
    job = None
    try:
        if os.name == "nt":
            job = _windows_job(p, memory_mb)
        out, err = p.communicate(stdin, timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(p, job)
        out, err = p.communicate()
    finally:
        _kill_tree(p, job)  # dọn process cháu còn sót, vd. clamscan khi worker crash giữa chừng
        if job:
            _k32().CloseHandle(job)
    return p.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"), timed_out


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


def _windows_job(p, memory_mb):
    """Gắn worker vào một Job Object: đóng job là kill cả cây; có thể giới hạn RAM cho cả job."""
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
    info.Basic.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
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


def scan(path, worker_args, passwords, hard_timeout: float, memory_mb: int | None = None):
    """Quét một file trong worker. Trả (report dict hoặc None, stdout của worker, lỗi hoặc None, hết_giờ)."""
    with tempfile.TemporaryDirectory(prefix="archiveguard-", ignore_cleanup_errors=True) as tmp:
        out = Path(tmp) / "report.json"
        env = {**os.environ, "TMP": tmp, "TEMP": tmp, "TMPDIR": tmp, "PYTHONIOENCODING": "utf-8",
               "PYTHONPATH": os.pathsep.join(filter(None, [str(PACKAGE_PARENT), os.environ.get("PYTHONPATH")]))}
        # cwd = thư mục tạm rỗng: `python -m` thêm cwd vào sys.path, không để file .py lạ ở thư mục người dùng
        # (vd. Downloads) che mất thư viện chuẩn
        cmd = [sys.executable, "-m", "archive_guard", str(Path(path).resolve()), "--_worker",
               "--json", str(out), *worker_args]
        request = json.dumps({"passwords": list(passwords)}).encode()
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
            last = (stderr.strip().splitlines() or ["không có thông báo lỗi"])[-1]
            return None, stdout, f"worker lỗi (mã thoát {code}): {last}", False
        return report, stdout, None, False
