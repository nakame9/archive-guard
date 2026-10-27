"""Luật phát hiện dựa trên tên file và nội dung (heuristic)."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path

from .extract import archive_kind

LOW, MEDIUM, HIGH, CRITICAL = 1, 2, 3, 4
SEVERITY_NAME = {LOW: "LOW", MEDIUM: "MEDIUM", HIGH: "HIGH", CRITICAL: "CRITICAL"}
SEVERITY_SCORE = {LOW: 10, MEDIUM: 30, HIGH: 60, CRITICAL: 100}

CATEGORIES = {
    "known_malware": "Mã độc đã biết",
    "trojan": "Trojan / ngụy trang",
    "keylogger": "Keylogger (ghi phím)",
    "worm": "Worm (tự lây lan)",
    "ransomware": "Ransomware (mã hóa tống tiền)",
    "stealer": "Stealer (đánh cắp dữ liệu)",
    "backdoor": "Backdoor / RAT (điều khiển từ xa)",
    "downloader": "Downloader / Dropper",
    "evasion": "Né tránh phát hiện",
    "archive_abuse": "Lạm dụng file nén (zip bomb, zip slip)",
    "generic": "Đáng chú ý",
}


@dataclass
class Finding:
    rule: str
    severity: int
    category: str
    title: str
    detail: str = ""
    engine: str = "heuristic"

    def to_dict(self):
        return {**asdict(self), "severity": SEVERITY_NAME[self.severity]}


# --- Tên file -------------------------------------------------------------------------------

EXEC_EXTS = {"exe", "dll", "msi", "msix", "appx", "jar", "bat", "cmd", "ps1", "psm1", "vbs",
             "sys", "ocx", "apk", "reg", "url"}
# Loại file hiếm khi hợp lệ trong file nén tải về, nhưng rất hay bị dùng để phát tán mã độc
RISKY_EXTS = {"scr", "pif", "com", "cpl", "hta", "vbe", "jse", "wsf", "wsh", "sct", "lnk", "scf",
              "chm", "xll", "iqy", "slk", "msc", "one", "gadget", "appref-ms",
              "settingcontent-ms", "library-ms"}
RUNNABLE_EXTS = EXEC_EXTS | RISKY_EXTS | {"js"}
DISK_IMAGE_EXTS = {"iso", "img", "vhd", "vhdx"}
# Đuôi "mồi" mà kẻ tấn công giả làm: invoice.pdf.exe, photo.jpg.scr…
DECOY_EXTS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg",
              "jpeg", "png", "gif", "bmp", "mp3", "mp4", "avi", "mkv", "mov", "wav", "zip", "rar", "7z"}
SCRIPT_EXTS = {"ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "sct",
               "py", "pyw", "sh", "php", "pl", "rb", "ahk", "au3", "html", "htm", "svg", "reg"}
# Ký tự điều khiển hướng chữ Unicode: "photo‮gpj.exe" hiển thị thành "photoexe.jpg"
BIDI_CHARS = "‪‫‬‭‮⁦⁧⁨⁩‎‏"


def basename(name: str) -> str:
    return name.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def ext_of(name: str) -> str:
    base = basename(name)
    return base.rsplit(".", 1)[-1].lower() if "." in base else ""


def _escapes(path: str) -> bool:
    return (path.startswith(("/", "\\")) or re.match(r"[A-Za-z]:", path) is not None
            or ".." in re.split(r"[\\/]", path))


def check_name(name: str, in_archive: bool, link: str = "") -> list[Finding]:
    base = basename(name)
    parts = base.lower().split(".")
    ext = ext_of(name)
    out = []
    if in_archive and _escapes(name):
        out.append(Finding("NAME.PATH_TRAVERSAL", HIGH, "archive_abuse",
                           "Đường dẫn thoát ra ngoài thư mục giải nén (Zip Slip)", name))
    if link and _escapes(link):
        out.append(Finding("NAME.PATH_TRAVERSAL", HIGH, "archive_abuse",
                           "Symlink trỏ ra ngoài thư mục giải nén", f"{name} -> {link}"))
    if any(c in base for c in BIDI_CHARS):
        out.append(Finding("NAME.BIDI", HIGH, "trojan",
                           "Tên file chứa ký tự đảo chiều Unicode để giả mạo đuôi file", repr(base)))
    if len(parts) >= 3 and ext in RUNNABLE_EXTS and parts[-2] in DECOY_EXTS:
        out.append(Finding("NAME.DOUBLE_EXT", HIGH, "trojan",
                           f"Đuôi kép giả mạo: trông như .{parts[-2]} nhưng thực ra là .{ext}", base))
    if ext in RUNNABLE_EXTS and re.search(r"[\s_]{6,}\.\w+$", base):
        out.append(Finding("NAME.PADDING", HIGH, "trojan",
                           "Chèn nhiều khoảng trắng để giấu đuôi thật của file", base))
    if ext in RISKY_EXTS:
        out.append(Finding("NAME.RISKY_TYPE", MEDIUM, "generic",
                           f"Loại file .{ext} hay bị dùng để phát tán mã độc"))
    elif ext in EXEC_EXTS and in_archive:
        out.append(Finding("NAME.EXECUTABLE", LOW, "generic", f"Có file thực thi/script .{ext}"))
    if ext in DISK_IMAGE_EXTS and in_archive:
        out.append(Finding("NAME.DISK_IMAGE", MEDIUM, "evasion",
                           f"Ảnh đĩa .{ext} – hay dùng để né cảnh báo Mark-of-the-Web của Windows"))
    if base.lower() == "autorun.inf":
        out.append(Finding("NAME.AUTORUN_INF", MEDIUM, "worm",
                           "autorun.inf – cơ chế tự chạy mà worm USB hay dùng"))
    if base.lower() == "vbaproject.bin":
        out.append(Finding("DOC.MACRO", MEDIUM, "downloader", "Tài liệu Office chứa macro VBA"))
    return out


# --- Loại file theo nội dung ----------------------------------------------------------------

def file_kind(data: bytes, name: str) -> str:
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        return "macho"
    if data[:4] == b"L\x00\x00\x00":
        return "lnk"
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"  # .doc, .xls, .ppt, .msi đời cũ
    kind = archive_kind(data[:512])
    if kind:
        return kind
    if ext_of(name) in SCRIPT_EXTS or data[:2] == b"#!":
        return "script"
    if data[:4] == b"%PDF":
        return "pdf"
    if data[:4] == b"ITSF":
        return "chm"  # file trợ giúp: tài liệu API hay nhắc tên hàm Windows, dò chuỗi sẽ báo nhầm
    if b"\x00" not in data[:8192]:
        return "text"
    return "unknown"


# --- Chỉ dấu hành vi trong nội dung ---------------------------------------------------------
# (mã luật, mức độ, nhóm, mô tả, [nhóm chuỗi…], số nhóm phải khớp, tổng số chuỗi phải khớp)
# Chuỗi được so khớp không phân biệt hoa thường, cả dạng ASCII lẫn UTF-16 (chuỗi Windows).
_INDICATORS = [
    ("KEYLOG.API", MEDIUM, "keylogger", "Dùng API bắt phím kèm theo dõi cửa sổ/clipboard",
     [["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetRawInputData",
       "WH_KEYBOARD_LL", "pynput.keyboard", "keyboard.on_press"],
      ["GetForegroundWindow", "GetWindowTextA", "GetWindowTextW", "GetKeyboardLayout",
       "MapVirtualKeyA", "MapVirtualKeyW", "ToUnicodeEx", "GetClipboardData", "win32gui"]], 2, 2),
    ("KEYLOG.MARKERS", HIGH, "keylogger", "Chứa nhãn ghi phím đặc trưng của keylogger",
     [["[BACKSPACE]", "[ENTER]", "[CAPSLOCK]", "[SHIFT]", "[CTRL]", "[ESC]", "[DEL]", "[TAB]",
       "Key.space", "Key.enter", "Key.backspace", "keylog"]], 1, 3),
    ("INJECT.PROCESS", HIGH, "trojan", "Tiêm mã vào tiến trình khác (process injection / hollowing)",
     [["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
       "RtlCreateUserThread", "QueueUserAPC", "SetThreadContext", "NtUnmapViewOfSection",
       "ZwUnmapViewOfSection"]], 1, 3),
    ("PERSIST.AUTOSTART", LOW, "trojan", "Tự khởi động cùng Windows (Run key, Startup, tác vụ lập lịch)",
     [["CurrentVersion\\Run", "Winlogon\\Shell", "Winlogon\\Userinit", "schtasks /create",
       "\\Start Menu\\Programs\\Startup"]], 1, 1),
    ("DOWNLOAD.API", MEDIUM, "downloader", "Tải file từ Internet về máy",
     [["URLDownloadToFileA", "URLDownloadToFileW", "URLDownloadToCacheFile", "certutil -urlcache",
       "certutil.exe -urlcache", "bitsadmin /transfer", "Start-BitsTransfer", ".DownloadFile("]], 1, 1),
    ("DOWNLOAD.EXEC_PS", HIGH, "downloader", "PowerShell tải mã từ Internet rồi thực thi ngay",
     [["IEX(", "IEX (", "Invoke-Expression", "| iex"],
      ["DownloadString(", "DownloadData(", "Net.WebClient", "Invoke-WebRequest", "Invoke-RestMethod",
       "iwr ", "irm "]], 2, 2),
    ("DOWNLOAD.SCRIPT_DROPPER", HIGH, "downloader", "Script tải file, ghi ra đĩa rồi chạy (dropper)",
     [["MSXML2.XMLHTTP", "MSXML2.ServerXMLHTTP", "Microsoft.XMLHTTP", "WinHttp.WinHttpRequest"],
      ["ADODB.Stream", "SaveToFile", "Scripting.FileSystemObject"],
      ["WScript.Shell", "Shell.Application", "ShellExecute"]], 3, 3),
    ("EXEC.PS_HIDDEN", HIGH, "evasion", "PowerShell chạy ẩn / chạy lệnh mã hóa base64",
     [["-EncodedCommand", "-enc ", "-w hidden", "-WindowStyle Hidden", "FromBase64String",
       "Reflection.Assembly]::Load"]], 1, 2),
    ("EVADE.DISABLE_AV", HIGH, "evasion", "Vô hiệu hóa AMSI / Windows Defender / tường lửa",
     [["AmsiUtils", "amsiInitFailed", "DisableRealtimeMonitoring", "Add-MpPreference -ExclusionPath",
       "DisableAntiSpyware", "sc stop WinDefend", "netsh advfirewall set allprofiles state off"]], 1, 1),
    ("EVADE.ANTI_VM", MEDIUM, "evasion", "Dò máy ảo/sandbox để né phân tích",
     [["VBoxService", "VBoxTray", "vmtoolsd", "vmwaretray", "SbieDll.dll",
       "wine_get_unix_file_name", "vboxhook.dll", "VBOX__"]], 1, 2),
    ("EVADE.UAC_BYPASS", HIGH, "evasion", "Vượt UAC để chiếm quyền quản trị",
     [["ms-settings\\Shell\\Open\\command", "mscfile\\shell\\open\\command"]], 1, 1),
    ("RANSOM.KILL_BACKUP", HIGH, "ransomware", "Xóa shadow copy/bản sao lưu – hành vi điển hình của ransomware",
     [["vssadmin delete shadows", "vssadmin.exe delete shadows", "shadowcopy delete",
       "wbadmin delete catalog", "recoveryenabled no", "bootstatuspolicy ignoreallfailures"]], 1, 1),
    ("RANSOM.NOTE", HIGH, "ransomware", "Chứa nội dung đòi tiền chuộc",
     [["your files have been encrypted", "your files are encrypted", "decrypt your files",
       "decryption key", "pay the ransom", "bitcoin wallet", ".onion", "tor browser"]], 1, 2),
    ("STEAL.BROWSER", HIGH, "stealer", "Đọc mật khẩu/cookie đã lưu của trình duyệt",
     [["\\Google\\Chrome\\User Data", "\\Microsoft\\Edge\\User Data", "\\Mozilla\\Firefox\\Profiles",
       "Login Data", "logins.json", "key4.db", "encrypted_key", "CryptUnprotectData"]], 1, 3),
    ("STEAL.WALLET_APPS", HIGH, "stealer", "Nhắm tới ví tiền ảo / Telegram / Discord",
     [["wallet.dat", "\\Electrum\\wallets", "\\Exodus\\", "\\Ethereum\\keystore",
       "Telegram Desktop\\tdata", "\\discord\\Local Storage\\leveldb",
       "nkbihfbeogaeaoehlefnkodbefgpgknn"]], 1, 2),
    ("STEAL.CREDENTIAL_DUMP", HIGH, "stealer", "Trích xuất mật khẩu Windows (mimikatz / dump LSASS)",
     [["sekurlsa::", "mimikatz", "comsvcs.dll, MiniDump", "comsvcs.dll MiniDump",
       "procdump -ma lsass"]], 1, 1),
    ("EXFIL.CHANNEL", MEDIUM, "stealer", "Gửi dữ liệu ra ngoài qua Telegram bot / Discord webhook / SMTP",
     [["api.telegram.org/bot", "discord.com/api/webhooks", "discordapp.com/api/webhooks",
       "smtp.gmail.com", "smtp.yandex", "pastebin.com/raw"]], 1, 1),
    ("BACKDOOR.REVERSE_SHELL", HIGH, "backdoor", "Reverse shell – cho kẻ tấn công điều khiển máy từ xa",
     [["/dev/tcp/", "nc -e /bin", "Invoke-PowerShellTcp", "Net.Sockets.TCPClient", "pty.spawn("]], 1, 1),
    ("BACKDOOR.KNOWN_RAT", HIGH, "backdoor", "Chứa tên họ RAT/stealer nổi tiếng",
     [["njRAT", "NanoCore", "DarkComet", "Remcos", "AsyncRAT", "QuasarRAT", "Quasar.Client", "DcRat",
       "XWorm", "AgentTesla"]], 1, 1),
    ("WORM.USB", HIGH, "worm", "Lây lan qua USB (ghi autorun.inf lên ổ đĩa di động)",
     [["autorun.inf"],
      ["GetDriveTypeA", "GetDriveTypeW", "GetLogicalDriveStringsA", "GetLogicalDriveStringsW",
       "DRIVE_REMOVABLE", "DriveType", "Win32_LogicalDisk"]], 2, 2),
    ("WORM.NETWORK", MEDIUM, "worm", "Lây lan qua mạng nội bộ (thư mục chia sẻ, ADMIN$)",
     [["\\ADMIN$", "\\C$\\", "\\IPC$", "NetShareEnum", "WNetEnumResourceA", "WNetEnumResourceW",
       "NetServerEnum", "WNetAddConnection2"]], 1, 2),
]
_INDICATORS = [(r, s, c, t, [frozenset(x.lower() for x in g) for g in groups], mg, mh)
               for r, s, c, t, groups, mg, mh in _INDICATORS]
_LOOKUP = {}  # biến thể đã chuyển chữ thường (ASCII / UTF-16LE) -> chuỗi gốc
for *_, _groups, _mg, _mh in _INDICATORS:
    for _s in set().union(*_groups):
        _LOOKUP[_s.encode()] = _s
        _LOOKUP[_s.encode("utf-16-le")] = _s

INDICATOR_KINDS = {"pe", "elf", "macho", "script", "lnk", "unknown"}
# shortcut: chỉ dò chuỗi trong 32 MB đầu + 4 MB cuối (~3 giây); file "độn" cho to thường
# giữ mã thật ở đầu. Chuyển sang Aho-Corasick (pyahocorasick) nếu cần quét trọn file lớn.
_HEAD, _TAIL = 32 << 20, 4 << 20
_VBA_OLE = "_VBA_PROJECT".encode("utf-16-le")


def check_content(data: bytes, kind: str, name: str) -> list[Finding]:
    out = []
    ext = ext_of(name)
    if kind in ("pe", "elf", "macho") and ext in DECOY_EXTS:
        out.append(Finding("NAME.CONTENT_MISMATCH", HIGH, "trojan",
                           f"Thực chất là file thực thi nhưng mang đuôi .{ext} để đánh lừa"))
    if kind == "ole" and _VBA_OLE in data:
        out.append(Finding("DOC.MACRO", MEDIUM, "downloader", "Tài liệu Office chứa macro VBA"))
    if kind in INDICATOR_KINDS:
        if len(data) > _HEAD + _TAIL:
            data = data[:_HEAD] + b"\n" + data[-_TAIL:]
        low = data.lower()  # bytes.lower() chỉ đổi A-Z nên an toàn với dữ liệu nhị phân
        found = {s for v, s in _LOOKUP.items() if v in low}
        for rule, sev, cat, title, groups, min_groups, min_hits in _INDICATORS:
            hits = [found & g for g in groups]
            matched = sorted(set().union(*hits))
            if sum(1 for h in hits if h) >= min_groups and len(matched) >= min_hits:
                out.append(Finding(rule, sev, cat, title, "khớp: " + ", ".join(matched[:6])))
    return out


# --- Danh sách mã băm -------------------------------------------------------------------------

def load_hashes(paths) -> dict[str, str]:
    """Đọc file mã băm MD5/SHA1/SHA256: mỗi dòng "mã [tên họ mã độc]", dòng '#' là chú thích.

    Trả về {mã băm: tên họ} (tên họ rỗng nếu dòng không ghi).
    """
    hashes = {}
    for p in paths:
        for line in Path(p).read_text(encoding="utf-8", errors="ignore").splitlines():
            token = line.split("#", 1)[0].replace('"', " ").split()
            if token and len(token[0]) in (32, 40, 64):
                hashes[token[0].lower()] = token[1] if len(token) > 1 else ""
    return hashes
