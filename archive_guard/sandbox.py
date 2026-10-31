"""Sandbox cấp hệ điều hành cho worker, áp TRƯỚC khi đọc byte đầu tiên của dữ liệu không tin cậy.

Linux – worker tự áp lên chính nó; process con (unrar, clamscan) thừa hưởng mọi hạn chế:
  1. RLIMIT_CORE = 0: crash không đổ nội dung file đang quét ra đĩa
  2. no_new_privs: không leo quyền qua file setuid (điều kiện để dùng Landlock/seccomp khi không phải root)
  3. mạng: network namespace rỗng (cần user namespace không đặc quyền) → không có card mạng nào
  4. Landlock: chỉ ĐỌC được file đầu vào, thư viện Python, thư mục hệ thống; chỉ GHI được thư mục tạm riêng;
     từ ABI 4 chặn cả kết nối/mở cổng TCP, từ ABI 6 chặn gửi tín hiệu ra ngoài sandbox
  5. seccomp (x86_64): chặn ptrace, mount, nạp module kernel, bpf, io_uring… và mọi socket không phải AF_UNIX
macOS – process cha bọc worker bằng sandbox-exec: chặn mạng, chặn ghi ngoài thư mục tạm (macos_wrap()).
Windows – chưa có sandbox file/mạng; chỉ có Job Object (RAM, CPU, kill cả cây) trong isolate.py.

Lớp nào không có trên máy thì bỏ qua và ghi lại trong báo cáo; --require-sandbox biến điều đó thành lỗi.
Chạy `python -m archive_guard.sandbox` để xem lớp nào hoạt động trên máy này.
"""
from __future__ import annotations

import ctypes
import errno
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

PACKAGE_PARENT = Path(__file__).resolve().parent.parent
SYSTEM_READ = ["/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin", "/etc", "/opt", "/proc", "/dev",
               "/var/lib/clamav", "/run/clamav"]  # ClamAV cần cơ sở dữ liệu chữ ký và socket của clamd

# --- Linux: Landlock ----------------------------------------------------------------------------
_SYS_CREATE_RULESET, _SYS_ADD_RULE, _SYS_RESTRICT_SELF = 444, 445, 446  # giống nhau trên mọi kiến trúc
_EXECUTE, _WRITE_FILE, _READ_FILE, _READ_DIR = 1 << 0, 1 << 1, 1 << 2, 1 << 3
_TRUNCATE, _IOCTL_DEV = 1 << 14, 1 << 15
_FILE_ONLY = _EXECUTE | _WRITE_FILE | _READ_FILE | _TRUNCATE | _IOCTL_DEV  # quyền áp được lên một FILE


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("fs", ctypes.c_uint64), ("net", ctypes.c_uint64), ("scoped", ctypes.c_uint64)]


class _PathBeneath(ctypes.Structure):
    _pack_ = 1  # struct landlock_path_beneath_attr được khai báo __packed
    _fields_ = [("allowed", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def _libc():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    return libc


def _call(fn, *args):
    r = fn(*args)
    if r < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return r


def _landlock(libc, read, write, block_tcp):
    abi = libc.syscall(ctypes.c_long(_SYS_CREATE_RULESET), None, ctypes.c_size_t(0), ctypes.c_uint32(1))
    if abi < 0:
        return False, f"không hỗ trợ ({errno.errorcode.get(ctypes.get_errno(), '?')})"
    fs = (1 << 13) - 1 | (1 << 13 if abi >= 2 else 0) | (_TRUNCATE if abi >= 3 else 0) | (_IOCTL_DEV if abi >= 5 else 0)
    attr = _RulesetAttr(fs, 0b11 if abi >= 4 and block_tcp else 0, 0b11 if abi >= 6 else 0)
    size = 24 if abi >= 6 else 16 if abi >= 4 else 8
    ruleset = _call(libc.syscall, ctypes.c_long(_SYS_CREATE_RULESET), ctypes.byref(attr), ctypes.c_size_t(size),
                    ctypes.c_uint32(0))
    try:
        rules = [(p, _EXECUTE | _READ_FILE | _READ_DIR) for p in read] + [(p, fs) for p in write]
        for path, access in rules:
            try:
                fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            except OSError:
                continue  # đường dẫn không tồn tại trên máy này
            try:
                if not stat.S_ISDIR(os.fstat(fd).st_mode):
                    access &= _FILE_ONLY
                rule = _PathBeneath(access & fs, fd)
                _call(libc.syscall, ctypes.c_long(_SYS_ADD_RULE), ctypes.c_int(ruleset), ctypes.c_int(1),
                      ctypes.byref(rule), ctypes.c_uint32(0))
            finally:
                os.close(fd)
        _call(libc.syscall, ctypes.c_long(_SYS_RESTRICT_SELF), ctypes.c_int(ruleset), ctypes.c_uint32(0))
    finally:
        os.close(ruleset)
    return True, f"bật (ABI {abi})" + (", chặn TCP" if abi >= 4 and block_tcp else "")


# --- Linux: seccomp -------------------------------------------------------------------------------
# Danh sách chặn cho x86_64. Không chặn execve: worker cần gọi unrar/clamscan (đã bị Landlock khóa theo).
_X86_64_DENY = {
    101: "ptrace", 310: "process_vm_readv", 311: "process_vm_writev", 165: "mount", 166: "umount2",
    155: "pivot_root", 161: "chroot", 246: "kexec_load", 320: "kexec_file_load", 175: "init_module",
    313: "finit_module", 176: "delete_module", 321: "bpf", 298: "perf_event_open", 250: "keyctl",
    248: "add_key", 249: "request_key", 308: "setns", 272: "unshare", 323: "userfaultfd",
    304: "open_by_handle_at", 172: "iopl", 173: "ioperm", 167: "swapon", 168: "swapoff", 169: "reboot",
    163: "acct", 164: "settimeofday", 227: "clock_settime", 179: "quotactl", 425: "io_uring_setup",
}
_SYS_SOCKET, _AF_UNIX, _SYS_SECCOMP = 41, 1, 317


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(_SockFilter))]


def seccomp_program():
    """Chương trình BPF: kiến trúc khác x86_64 → kill; syscall trong danh sách chặn hoặc socket mạng → EPERM."""
    ld, jeq, jge, ret = 0x20, 0x15, 0x35, 0x06
    allow, deny, kill = 0x7FFF0000, 0x00050000 | errno.EPERM, 0x80000000
    deny_nrs = sorted(_X86_64_DENY)
    n = len(deny_nrs)
    deny_at, sock_at = 10 + n, 7 + n  # vị trí lệnh "trả EPERM" và khối kiểm tra socket
    prog = [(ld, 0, 0, 4), (jeq, 1, 0, 0xC000003E), (ret, 0, 0, kill),  # seccomp_data.arch == AUDIT_ARCH_X86_64
            (ld, 0, 0, 0), (jge, deny_at - 5, 0, 0x40000000)]           # seccomp_data.nr; chặn ABI x32
    prog += [(jeq, deny_at - (5 + i) - 1, 0, nr) for i, nr in enumerate(deny_nrs)]
    prog += [(jeq, sock_at - (5 + n) - 1, 0, _SYS_SOCKET), (ret, 0, 0, allow),
             (ld, 0, 0, 16), (jeq, 0, 1, _AF_UNIX), (ret, 0, 0, allow),  # args[0] = domain của socket()
             (ret, 0, 0, deny)]
    assert len(prog) == deny_at + 1 and prog[sock_at] == (ld, 0, 0, 16)
    return prog


def _seccomp(libc):
    if platform.machine() != "x86_64":
        return False, f"bỏ qua: chỉ hỗ trợ x86_64 (máy này: {platform.machine()})"
    prog = seccomp_program()
    arr = (_SockFilter * len(prog))(*[_SockFilter(*ins) for ins in prog])
    fprog = _SockFprog(len(prog), arr)
    # SECCOMP_SET_MODE_FILTER + SECCOMP_FILTER_FLAG_TSYNC: áp cho mọi luồng của process
    _call(libc.syscall, ctypes.c_long(_SYS_SECCOMP), ctypes.c_uint(1), ctypes.c_uint(1), ctypes.byref(fprog))
    return True, f"bật (chặn {len(_X86_64_DENY)} syscall + socket mạng)"


def _linux(read, write):
    import resource

    libc = _libc()
    status = {}
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    _call(libc.prctl, 38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
    status["no_new_privs"] = "bật"
    try:  # CLONE_NEWUSER | CLONE_NEWNET: phải làm trước seccomp (seccomp chặn unshare)
        _call(libc.unshare, 0x10000000 | 0x40000000)
        netns = True
    except OSError as e:
        netns = False
        status["network_namespace"] = f"không được ({e.strerror})"
    else:
        status["network_namespace"] = "bật (không có card mạng)"
    fs_ok, status["landlock"] = _guard(lambda: _landlock(libc, read, write, block_tcp=True))
    sc_ok, status["seccomp"] = _guard(lambda: _seccomp(libc))
    status["filesystem_restricted"] = fs_ok
    status["network_blocked"] = netns or sc_ok  # seccomp chặn tạo mọi socket không phải AF_UNIX
    return status


def _guard(fn):
    try:
        return fn()
    except OSError as e:
        return False, f"lỗi: {e.strerror or e}"


# --- Điểm vào -------------------------------------------------------------------------------------

def read_paths(inputs):
    paths = {*map(str, inputs), sys.prefix, sys.exec_prefix, sys.base_prefix, sys.base_exec_prefix,
             os.path.dirname(os.path.realpath(sys.executable)), str(PACKAGE_PARENT), *SYSTEM_READ}
    return sorted(paths | {p for p in sys.path if p})


def apply(inputs, tmp, outer=None):
    """Áp sandbox lên CHÍNH process này. inputs: file được phép đọc; tmp: thư mục duy nhất được ghi.

    outer: sandbox do process cha đã bọc sẵn (macOS sandbox-exec). Trả về trạng thái từng lớp.
    """
    if sys.platform.startswith("linux"):
        return _linux(read_paths(inputs), [str(tmp), "/dev/null"])
    if outer:
        return {"sandbox_exec": "bật (chặn mạng, chặn ghi ngoài thư mục tạm)",
                "filesystem_restricted": True, "network_blocked": True}
    return {"note": "chưa có sandbox file/mạng trên hệ điều hành này (chỉ cô lập process: RAM, CPU, kill cả cây)",
            "filesystem_restricted": False, "network_blocked": False}


def missing(status) -> list[str]:
    """Các lớp bắt buộc còn thiếu (cho --require-sandbox): giới hạn truy cập file và chặn mạng."""
    return [name for key, name in (("filesystem_restricted", "giới hạn truy cập file"),
                                   ("network_blocked", "chặn mạng")) if not status.get(key)]


def macos_wrap(cmd, tmp):
    """macOS: bọc lệnh worker bằng sandbox-exec. Trả về (lệnh mới, có bọc được không)."""
    exe = shutil.which("sandbox-exec")
    if sys.platform != "darwin" or not exe:
        return cmd, False
    real = os.path.realpath(tmp).replace("\\", "\\\\").replace('"', '\\"')
    profile = ("(version 1)(allow default)(deny network*)(deny file-write*)"
               f'(allow file-write* (subpath "{real}") (literal "/dev/null") (literal "/dev/dtracehelper"))')
    return [exe, "-p", profile, *cmd], True


# --- Tự kiểm tra: python -m archive_guard.sandbox ---------------------------------------------------

_PROBE = r"""
import json, os, socket, sys, ctypes
sys.path.insert(0, sys.argv[4])
from archive_guard import sandbox
tmp, outside, secret = sys.argv[1], sys.argv[2], sys.argv[3]
status = sandbox.apply([], tmp, outer=os.environ.get("AG_OUTER"))
def ok(fn):
    try:
        fn(); return True
    except OSError:
        return False
res = {"status": status,
       "ghi_thu_muc_tam": ok(lambda: open(os.path.join(tmp, "a"), "w").write("x")),
       "ghi_ngoai_sandbox": ok(lambda: open(os.path.join(outside, "b"), "w").write("x")),
       "doc_file_ca_nhan": ok(lambda: open(secret).read()),
       "mo_socket_mang": ok(lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM).close())}
if sys.platform.startswith("linux"):
    libc = ctypes.CDLL(None, use_errno=True)
    res["ptrace"] = libc.ptrace(0, 0, None, None) == 0  # PTRACE_TRACEME
print(json.dumps(res))
"""


def self_test() -> dict:
    """Chạy một process con, áp sandbox rồi thử các thao tác bị cấm. True = thao tác vẫn làm được."""
    with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside, \
            tempfile.TemporaryDirectory() as home:
        secret = os.path.join(home, "secret.txt")
        Path(secret).write_text("bí mật")
        cmd = [sys.executable, "-c", _PROBE, tmp, outside, secret, str(PACKAGE_PARENT)]
        cmd, wrapped = macos_wrap(cmd, tmp)
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", **({"AG_OUTER": "sandbox-exec"} if wrapped else {})}
        out = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=tmp, timeout=60)
        if out.returncode:
            raise RuntimeError(out.stderr.strip()[-500:])
        return json.loads(out.stdout)


if __name__ == "__main__":
    result = self_test()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if os.environ.get("GITHUB_ACTIONS"):  # hiện thành annotation trên GitHub: xem được mà không cần đăng nhập
        where = os.environ.get("AG_CONTEXT") or sys.platform
        print(f"::notice title=sandbox {where}::" + json.dumps(result, ensure_ascii=False))
