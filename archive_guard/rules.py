"""Luật phát hiện dựa trên tên file và nội dung (heuristic)."""
from __future__ import annotations

import math
import re
import struct
from collections import Counter
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
    """severity = mức tác hại NẾU đúng là mã độc; confidence = mức chắc chắn rằng đó là hành vi độc hại."""
    rule: str
    severity: int
    category: str
    title: str
    detail: str = ""
    engine: str = "heuristic"
    confidence: str = ""  # low | medium | high; để trống = lấy theo RULE_META
    attack: str = ""      # mã kỹ thuật MITRE ATT&CK

    def __post_init__(self):
        confidence, attack = RULE_META.get(self.rule, _META_DEFAULT)
        self.confidence = self.confidence or confidence
        self.attack = self.attack or attack

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
# Ký tự điều khiển hướng chữ Unicode: "photo\u202egpj.exe" hiển thị thành "photoexe.jpg"
BIDI_CHARS = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f"


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
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        out.append(Finding("NAME.CONTROL_CHARS", MEDIUM, "evasion",
                           "Tên file chứa ký tự điều khiển – mỗi công cụ hiển thị một kiểu", repr(name)))
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
    if "/macrosheets/" in "/" + name.lower().replace("\\", "/"):
        out.append(Finding("DOC.XLM_MACRO", MEDIUM, "downloader", "Bảng tính chứa macro Excel 4.0 (XLM)", name))
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
# Nhóm chuỗi dùng chung giữa luật "khả năng" và luật ngữ cảnh bên dưới
_KEY_CAPTURE = ["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetRawInputData",
                "WH_KEYBOARD_LL", "pynput.keyboard", "keyboard.on_press"]
_EXFIL = ["api.telegram.org/bot", "discord.com/api/webhooks", "discordapp.com/api/webhooks",
          "smtp.gmail.com", "smtp.yandex", "pastebin.com/raw"]
_INJECT_API = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
               "RtlCreateUserThread", "QueueUserAPC", "SetThreadContext", "NtUnmapViewOfSection",
               "ZwUnmapViewOfSection"]
_BROWSER_CREDS = ["\\Google\\Chrome\\User Data", "\\Microsoft\\Edge\\User Data", "\\Mozilla\\Firefox\\Profiles",
                  "Login Data", "logins.json", "key4.db", "encrypted_key", "CryptUnprotectData"]
_WALLETS = ["wallet.dat", "\\Electrum\\wallets", "\\Exodus\\", "\\Ethereum\\keystore",
            "Telegram Desktop\\tdata", "\\discord\\Local Storage\\leveldb", "nkbihfbeogaeaoehlefnkodbefgpgknn"]
_ANTI_VM = ["VBoxService", "VBoxTray", "vmtoolsd", "vmwaretray", "SbieDll.dll",
            "wine_get_unix_file_name", "vboxhook.dll", "VBOX__"]
_DOWNLOAD_API = ["URLDownloadToFileA", "URLDownloadToFileW", "URLDownloadToCacheFile", "certutil -urlcache",
                 "certutil.exe -urlcache", "bitsadmin /transfer", "Start-BitsTransfer", ".DownloadFile("]

_INDICATORS = [
    # --- Khả năng (confidence "low", xem RULE_META): phần mềm hợp pháp cũng dùng, một mình không đủ kết luận
    ("KEYLOG.API", MEDIUM, "keylogger", "Dùng API bắt phím kèm theo dõi cửa sổ/clipboard",
     [_KEY_CAPTURE,
      ["GetForegroundWindow", "GetWindowTextA", "GetWindowTextW", "GetKeyboardLayout",
       "MapVirtualKeyA", "MapVirtualKeyW", "ToUnicodeEx", "GetClipboardData", "win32gui"]], 2, 2),
    ("KEYLOG.MARKERS", HIGH, "keylogger", "Chứa nhãn ghi phím đặc trưng của keylogger",
     [["[BACKSPACE]", "[ENTER]", "[CAPSLOCK]", "[SHIFT]", "[CTRL]", "[ESC]", "[DEL]", "[TAB]",
       "Key.space", "Key.enter", "Key.backspace", "keylog"]], 1, 3),
    ("INJECT.PROCESS", HIGH, "trojan", "Có API tiêm mã vào tiến trình khác (debugger, công cụ hook cũng dùng)",
     [_INJECT_API], 1, 3),
    ("PERSIST.AUTOSTART", LOW, "trojan", "Tự khởi động cùng Windows (Run key, Startup, tác vụ lập lịch)",
     [["CurrentVersion\\Run", "Winlogon\\Shell", "Winlogon\\Userinit", "schtasks /create",
       "\\Start Menu\\Programs\\Startup"]], 1, 1),
    ("DOWNLOAD.API", MEDIUM, "downloader", "Tải file từ Internet về máy",
     [_DOWNLOAD_API], 1, 1),
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
     [_ANTI_VM], 1, 2),
    ("EVADE.UAC_BYPASS", HIGH, "evasion", "Vượt UAC để chiếm quyền quản trị",
     [["ms-settings\\Shell\\Open\\command", "mscfile\\shell\\open\\command"]], 1, 1),
    ("RANSOM.KILL_BACKUP", HIGH, "ransomware", "Xóa shadow copy/bản sao lưu – hành vi điển hình của ransomware",
     [["vssadmin delete shadows", "vssadmin.exe delete shadows", "shadowcopy delete",
       "wbadmin delete catalog", "recoveryenabled no", "bootstatuspolicy ignoreallfailures"]], 1, 1),
    # Phải có CẢ lời đòi tiền chuộc LẪN cách trả tiền/liên lạc: ".onion" hay "decryption key" đứng một mình
    # là chuỗi bình thường trong thư viện mạng/TLS (vd. esbuild viết bằng Go)
    ("RANSOM.NOTE", HIGH, "ransomware", "Chứa nội dung đòi tiền chuộc",
     [["your files have been encrypted", "your files are encrypted", "all your files", "decrypt your files",
       "recover your files", "pay the ransom", "files have been locked"],
      ["bitcoin", "monero", ".onion", "tor browser", "decryption key", "decryptor", "btc wallet"]], 2, 2),
    ("STEAL.BROWSER", HIGH, "stealer", "Đọc mật khẩu/cookie đã lưu của trình duyệt",
     [_BROWSER_CREDS], 1, 3),
    ("STEAL.WALLET_APPS", HIGH, "stealer", "Nhắm tới ví tiền ảo / Telegram / Discord",
     [_WALLETS], 1, 2),
    ("STEAL.CREDENTIAL_DUMP", HIGH, "stealer", "Trích xuất mật khẩu Windows (mimikatz / dump LSASS)",
     [["sekurlsa::", "mimikatz", "comsvcs.dll, MiniDump", "comsvcs.dll MiniDump",
       "procdump -ma lsass"]], 1, 1),
    ("EXFIL.CHANNEL", MEDIUM, "stealer", "Gửi dữ liệu ra ngoài qua Telegram bot / Discord webhook / SMTP",
     [_EXFIL], 1, 1),
    # Cần CẢ phần mở shell LẪN phần kết nối mạng: "pty.spawn(" một mình có trong ví dụ của thư viện rich (pip)
    ("BACKDOOR.REVERSE_SHELL", HIGH, "backdoor", "Reverse shell – cho kẻ tấn công điều khiển máy từ xa",
     [["pty.spawn(", "os.dup2(", "/bin/sh -i", "bash -i", "nc -e /bin", "Invoke-PowerShellTcp"],
      ["/dev/tcp/", "socket.socket(", ".connect((", "Net.Sockets.TCPClient"]], 2, 2),
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
    # --- Luật ngữ cảnh: KHẢ NĂNG + bằng chứng bổ trợ trong CÙNG một file → hành vi (chuỗi kỹ thuật ATT&CK)
    ("KEYLOG.EXFIL", HIGH, "keylogger", "Bắt phím VÀ gửi dữ liệu ra ngoài – chuỗi hành vi của keylogger",
     [_KEY_CAPTURE, _EXFIL], 2, 2),
    ("STEAL.EXFIL", HIGH, "stealer", "Đọc mật khẩu/ví tiền ảo VÀ gửi dữ liệu ra ngoài – chuỗi hành vi của stealer",
     [_BROWSER_CREDS + _WALLETS, _EXFIL], 2, 2),
    ("INJECT.LOADER", HIGH, "trojan", "Tiêm mã vào tiến trình khác VÀ né máy ảo/tải payload – chuỗi hành vi của loader",
     [_INJECT_API, _ANTI_VM + _DOWNLOAD_API], 2, 3),
]

# Phân loại từng mã luật: (độ tin cậy, kỹ thuật MITRE ATT&CK – https://attack.mitre.org).
#   "low"    = KHẢ NĂNG: API/chuỗi mà phần mềm hợp pháp cũng dùng (thư viện bàn phím, debugger, bộ cài…).
#              Một mình không đủ để gắn cờ – xem score_and_verdict() trong scanner.py.
#   "medium" = HÀNH VI hoặc dấu hiệu cụ thể, nhưng vẫn có thể gặp ở công cụ hợp pháp.
#   "high"   = bằng chứng mạnh, hiếm gặp ở phần mềm hợp pháp (ngụy trang tên file, lệnh xóa bản sao lưu, mã băm…).
RULE_META = {
    "KEYLOG.API": ("low", "T1056.001"), "INJECT.PROCESS": ("low", "T1055"),
    "PERSIST.AUTOSTART": ("low", "T1547.001"), "DOWNLOAD.API": ("low", "T1105"),
    "EVADE.ANTI_VM": ("low", "T1497.001"), "EXFIL.CHANNEL": ("low", "T1567"),
    "WORM.NETWORK": ("low", "T1021.002"), "NAME.EXECUTABLE": ("low", "T1204.002"),
    "PACKER.NAME": ("medium", "T1027.002"),
    "KEYLOG.MARKERS": ("medium", "T1056.001"), "DOWNLOAD.SCRIPT_DROPPER": ("medium", "T1105"),
    "EXEC.PS_HIDDEN": ("medium", "T1059.001"), "STEAL.BROWSER": ("medium", "T1555.003"),
    "STEAL.WALLET_APPS": ("medium", "T1005"), "BACKDOOR.REVERSE_SHELL": ("medium", "T1059"),
    "BACKDOOR.KNOWN_RAT": ("medium", ""), "WORM.USB": ("medium", "T1091"),
    "NAME.RISKY_TYPE": ("medium", "T1204.002"), "NAME.DISK_IMAGE": ("medium", "T1553.005"),
    "NAME.AUTORUN_INF": ("medium", "T1091"), "NAME.PATH_TRAVERSAL": ("medium", ""),
    "DOC.MACRO": ("medium", "T1059.005"), "PACKER.ENTROPY": ("medium", "T1027.002"),
    "KEYLOG.EXFIL": ("high", "T1056.001"), "STEAL.EXFIL": ("high", "T1555"), "INJECT.LOADER": ("medium", "T1055"),
    "DOWNLOAD.EXEC_PS": ("high", "T1059.001"), "EVADE.DISABLE_AV": ("high", "T1562.001"),
    "EVADE.UAC_BYPASS": ("high", "T1548.002"), "RANSOM.KILL_BACKUP": ("high", "T1490"),
    "RANSOM.NOTE": ("high", "T1486"), "STEAL.CREDENTIAL_DUMP": ("high", "T1003.001"),
    "NAME.DOUBLE_EXT": ("high", "T1036.007"), "NAME.BIDI": ("high", "T1036.002"),
    "NAME.PADDING": ("high", "T1036"), "NAME.CONTENT_MISMATCH": ("high", "T1036.008"),
    "HASH.KNOWN_BAD": ("high", ""), "CLAMAV": ("high", ""),
    "ARCHIVE.ENCRYPTED_EXEC": ("medium", "T1027.013"),
    "DOC.MACRO_AUTOEXEC_EXEC": ("medium", "T1059.005"), "DOC.REMOTE_RESOURCE": ("high", "T1221"),
    "DOC.XLM_MACRO": ("medium", "T1059"), "LNK.LOLBIN": ("medium", "T1218"),
    "LNK.PADDED_ARGS": ("medium", "T1027"), "EXEC.PS_ENCODED": ("medium", "T1027.010"),
    "ENTROPY.ENCRYPTED_BLOB": ("low", "T1027.013"), "ARCHIVE.OVERLAP": ("high", "T1499"),
    "ARCHIVE.HIDDEN_ENTRY": ("medium", "T1027"), "NAME.CONTROL_CHARS": ("medium", "T1036"),
}
_META_DEFAULT = ("medium", "")  # ARCHIVE.*, YARA.* (YARA tự đặt theo meta của luật)
# Tên họ mã độc chỉ tính khi đứng ĐẦU một từ: trình biên dịch Rust ghép chuỗi sát nhau nên
# "Vendored" + "crates" tạo ra "…dcrat…" (báo nhầm ở ruff, uv, turbo…). Phía sau thì cho tự do (DcRatBuilder).
_WORD_START_RULES = {"BACKDOOR.KNOWN_RAT"}
_WORD_START = {x.lower() for r, _s, _c, _t, groups, _mg, _mh in _INDICATORS if r in _WORD_START_RULES
               for g in groups for x in g}
_INDICATORS = [(r, s, c, t, [frozenset(x.lower() for x in g) for g in groups], mg, mh)
               for r, s, c, t, groups, mg, mh in _INDICATORS]
_LOOKUP = {}  # biến thể đã chuyển chữ thường (ASCII / UTF-16LE) -> chuỗi gốc
for *_, _groups, _mg, _mh in _INDICATORS:
    for _s in set().union(*_groups):
        _LOOKUP[_s.encode()] = _s
        _LOOKUP[_s.encode("utf-16-le")] = _s
_BOUNDED = {}  # biến thể cần ranh giới từ -> regex kiểm tra ký tự đứng trước không phải chữ/số
for _s in _WORD_START:
    _BOUNDED[_s.encode()] = re.compile(rb"(?<![a-z0-9])" + re.escape(_s.encode()))
    _BOUNDED[_s.encode("utf-16-le")] = re.compile(rb"(?<![a-z0-9]\x00)" + re.escape(_s.encode("utf-16-le")))

INDICATOR_KINDS = {"pe", "elf", "macho", "script", "lnk", "unknown"}
_CHUNK = 8 << 20  # quét từng khúc 8 MB để bộ nhớ không tăng gấp đôi với file lớn
_OVERLAP = max(map(len, _LOOKUP)) - 1  # chuỗi nằm vắt qua ranh giới hai khúc vẫn được tìm thấy


def _whole_token(v: bytes, low: bytes, raw: bytes) -> bool:
    """Tên họ mã độc phải là một token: trước nó không phải chữ/số, sau nó không phải chữ THƯỜNG.

    Chữ hoa phía sau vẫn được (CamelCase: "AsyncRATClient", "DcRatBuilder"), còn "dcrates" thì không.
    """
    utf16 = v.endswith(b"\x00")
    for m in _BOUNDED[v].finditer(low):
        nxt = raw[m.end(): m.end() + 2]
        if not (nxt[:1].islower() and (not utf16 or nxt[1:2] == b"\x00")):
            return True
    return False


def _yara_lookup():
    """Mọi chỉ dấu trong MỘT luật YARA (ascii wide nocase = đúng các biến thể trong _LOOKUP). None nếu thiếu yara."""
    try:
        import yara
    except ImportError:
        return None
    strings = sorted(set(_LOOKUP.values()))
    defs = " ".join(f'$s{i} = "{x.replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}" ascii wide nocase'
                    for i, x in enumerate(strings))
    return yara.compile(source=f"rule indicators {{ strings: {defs} condition: any of them }}"), strings, yara.Error


_YARA = _yara_lookup()


def _find_strings(data: bytes) -> set[str]:
    """Tìm mọi chỉ dấu trong TOÀN BỘ dữ liệu: YARA (Aho-Corasick, nhanh) nếu có, không thì vòng lặp Python."""
    if _YARA:
        compiled, strings, error = _YARA
        try:
            # cảnh báo "too many matches" (dữ liệu lặp lại) không ảnh hưởng: chỉ cần biết chuỗi có xuất hiện
            matches = compiled.match(data=data, warnings_callback=lambda *_: 0)  # 0 = CALLBACK_CONTINUE
            hits = {strings[int(sm.identifier[2:])] for m in matches for sm in m.strings}
        except error:  # vd. quá nhiều lần khớp: dùng cách cũ, chậm nhưng không bỏ sót
            return _find_strings_loop(data, _LOOKUP)
        bounded = hits & _WORD_START  # tên họ mã độc: YARA chỉ là bước lọc, ranh giới token kiểm tra như cũ
        return (hits - bounded) | _find_strings_loop(data, {v: x for v, x in _LOOKUP.items() if x in bounded})
    return _find_strings_loop(data, _LOOKUP)


def _find_strings_loop(data: bytes, lookup: dict) -> set[str]:
    """Cách dò cũ (~8 MB/s): so khớp từng chuỗi trên từng khúc 8 MB đã chuyển chữ thường."""
    pending, found = dict(lookup), set()
    if not pending:
        return found
    for start in range(0, len(data), _CHUNK):
        # lùi thêm 2 byte để kiểm tra được ký tự đứng trước chuỗi (UTF-16 dùng 2 byte/ký tự)
        raw = data[max(0, start - _OVERLAP - 2): start + _CHUNK]
        low = raw.lower()  # bytes.lower() chỉ đổi A-Z
        for v in [v for v in pending if v in low and (v not in _BOUNDED or _whole_token(v, low, raw))]:
            found.add(pending.pop(v))
        if not pending:
            break
    return found
_VBA_OLE = "_VBA_PROJECT".encode("utf-16-le")


def check_content(data: bytes, kind: str, name: str) -> list[Finding]:
    out = []
    ext = ext_of(name)
    if kind in ("pe", "elf", "macho") and ext in DECOY_EXTS:
        out.append(Finding("NAME.CONTENT_MISMATCH", HIGH, "trojan",
                           f"Thực chất là file thực thi nhưng mang đuôi .{ext} để đánh lừa"))
    if kind == "ole" and _VBA_OLE in data:
        out.append(Finding("DOC.MACRO", MEDIUM, "downloader", "Tài liệu Office chứa macro VBA"))
    if kind == "pe":
        out += check_packer(data)
    elif kind in ("elf", "macho") and b"UPX!" in data[:4096]:
        out.append(Finding("PACKER.NAME", LOW, "evasion", "File thực thi bị nén bằng UPX"))
    if kind in INDICATOR_KINDS:
        out += _indicator_findings(data)
    if kind == "ole":
        out += check_vba(data)
    elif kind == "lnk":
        out += check_lnk(data)
    elif kind in ("script", "text"):
        out += check_encoded_powershell(data.decode("latin-1"))
        if ext == "rels":
            out += check_rels(data)
    elif kind == "unknown":
        out += check_blob_entropy(data)
    return out


def _indicator_findings(data: bytes, where: str = "") -> list[Finding]:
    found = _find_strings(data)
    out = []
    for rule, sev, cat, title, groups, min_groups, min_hits in _INDICATORS:
        hits = [found & g for g in groups]
        matched = sorted(set().union(*hits))
        if sum(1 for h in hits if h) >= min_groups and len(matched) >= min_hits:
            out.append(Finding(rule, sev, cat, title, where + "khớp: " + ", ".join(matched[:6])))
    return out


# --- Macro VBA: mã nguồn nằm trong vbaProject.bin dưới dạng nén MS-OVBA, dò chuỗi thô không thấy được ------------

def _ovba_decompress(data: bytes, start: int, limit: int = 1 << 20) -> bytes:
    """Giải nén MS-OVBA (MS-OVBA 2.4.1) từ data[start]; dừng ở lỗi đầu tiên, trả phần đã giải nén được."""
    if data[start:start + 1] != b"\x01":
        return b""
    out, pos = bytearray(), start + 1
    while pos + 2 <= len(data) and len(out) < limit:
        header = int.from_bytes(data[pos:pos + 2], "little")
        if (header >> 12) & 0b111 != 0b011:  # chữ ký của mỗi khúc
            break
        chunk_end, pos, base = min(pos + (header & 0x0FFF) + 3, len(data)), pos + 2, len(out)
        if not header & 0x8000:  # khúc không nén: 4096 byte nguyên văn
            out += data[pos:pos + 4096]
            pos = chunk_end
            continue
        while pos < chunk_end:
            flags, pos = data[pos], pos + 1
            for bit in range(8):
                if pos >= chunk_end:
                    break
                if not flags >> bit & 1:
                    out.append(data[pos])
                    pos += 1
                    continue
                token, pos = int.from_bytes(data[pos:pos + 2], "little"), pos + 2
                done = len(out) - base
                if done == 0:
                    return bytes(out)  # dữ liệu hỏng: token sao chép ở đầu khúc
                bits = max((done - 1).bit_length(), 4)
                offset, length = (token >> (16 - bits)) + 1, (token & (0xFFFF >> bits)) + 3
                if offset > done:
                    return bytes(out)
                for _ in range(length):
                    out.append(out[-offset])
    return bytes(out)


def vba_source(data: bytes, limit: int = 4 << 20) -> bytes:
    """Mã nguồn VBA trong file OLE: tìm các module nén (bắt đầu bằng "Attribute VB_Name") và giải nén."""
    out, pos = bytearray(), data.find(b"\x00Attribut")
    while pos >= 3 and len(out) < limit:
        out += _ovba_decompress(data, pos - 3, limit - len(out)) + b"\n"
        pos = data.find(b"\x00Attribut", pos + 1)
    return bytes(out)


_VBA_AUTOEXEC = re.compile(rb"(?i)\b(auto_?open|auto_?close|autoexec|document_open|document_close|documentopen|"
                           rb"workbook_open|workbook_beforeclose|workbook_activate)\b")
_VBA_EXEC = re.compile(rb"(?i)(\bshell\s*\(|wscript\.shell|shell\.application|urldownloadtofile|xmlhttp|"
                       rb"winhttp|adodb\.stream|powershell|cmd(\.exe)?\s+/c|mshta|rundll32|regsvr32|callbyname|"
                       rb"lib\s+\"(kernel32|urlmon|ntdll)|virtualalloc|rtlmovememory|createthread|executeexcel4macro)")


def check_vba(data: bytes) -> list[Finding]:
    source = vba_source(data)
    if not source:
        return []
    out = _indicator_findings(source, "trong mã VBA đã giải nén – ")
    auto, run = _VBA_AUTOEXEC.search(source), _VBA_EXEC.findall(source)
    if auto and run:
        calls = sorted({m[0].decode("latin-1").strip().lower() for m in run})
        out.append(Finding("DOC.MACRO_AUTOEXEC_EXEC", HIGH, "downloader",
                           "Macro tự chạy khi mở tài liệu VÀ gọi lệnh/tải file",
                           f"{auto.group(0).decode('latin-1')} + {', '.join(calls[:5])}"))
    return out


# --- Tài nguyên ngoài trong Office Open XML (remote template, Follina…) ------------------------------------------

_REL = re.compile(rb"<Relationship\b[^>]*>", re.I)
_REL_RISKY_TYPE = re.compile(rb"Type=\"[^\"]*/(attachedTemplate|oleObject|frame|subDocument)\"", re.I)
_REL_EXTERNAL_TARGET = re.compile(rb"Target=\"\s*((https?|ftp|file|ms-msdt|mhtml|search-ms):|\\\\)[^\"]*\"", re.I)


def check_rels(data: bytes) -> list[Finding]:
    """Tài liệu tải template/đối tượng từ nơi khác khi mở (T1221). Liên kết thường (hyperlink) không tính."""
    hits = [m.group(0) for m in _REL.finditer(data) if b"External" in m.group(0)
            and _REL_RISKY_TYPE.search(m.group(0)) and _REL_EXTERNAL_TARGET.search(m.group(0))]
    if not hits:
        return []
    target = _REL_EXTERNAL_TARGET.search(hits[0]).group(0).decode("utf-8", "replace")
    return [Finding("DOC.REMOTE_RESOURCE", HIGH, "downloader",
                    "Tài liệu tự tải template/đối tượng từ bên ngoài khi mở", target[:200])]


# --- PowerShell -EncodedCommand: giải mã base64 rồi dò tiếp ----------------------------------------------------

_PS_ENCODED = re.compile(r"(?i)(?:^|[\s\"'])[-/](?:ec|" + "|".join("encodedcommand"[:i] for i in range(14, 0, -1))
                         + r")\s+['\"]?([A-Za-z0-9+/]{16,}={0,2})")


def _decode_ps(arg: str) -> str:
    import base64
    import binascii
    try:
        text = base64.b64decode(arg + "=" * (-len(arg) % 4)).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError):
        return ""
    printable = sum(" " <= c <= "~" or c in "\r\n\t" for c in text)  # lệnh PowerShell thật gần như toàn ASCII
    return text if len(text) >= 8 and printable >= 0.9 * len(text) else ""


def check_encoded_powershell(text: str, where: str = "") -> list[Finding]:
    if "powershell" not in text.lower() and "pwsh" not in text.lower():
        return []
    decoded = [d for d in (_decode_ps(m.group(1)) for m in _PS_ENCODED.finditer(text[:4 << 20])) if d]
    if not decoded:
        return []
    joined = "\n".join(decoded)
    return [Finding("EXEC.PS_ENCODED", MEDIUM, "evasion", "Lệnh PowerShell được mã hóa base64 (-EncodedCommand)",
                    where + repr(joined[:160]))] + _indicator_findings(
        joined.encode("utf-8"), where + "trong lệnh -EncodedCommand đã giải mã – ")


# --- Shortcut .lnk -------------------------------------------------------------------------------------------

LOLBINS = {"cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
           "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "conhost.exe", "forfiles.exe",
           "curl.exe", "schtasks.exe", "wmic.exe", "hh.exe", "cmstp.exe", "msbuild.exe", "installutil.exe",
           "explorer.exe", "finger.exe", "ftp.exe", "regasm.exe", "regsvcs.exe", "odbcconf.exe", "pcalua.exe"}


def parse_lnk(data: bytes) -> dict:
    """Shell Link (MS-SHLLINK): đường dẫn đích (LinkInfo + RELATIVE_PATH) và các chuỗi StringData."""
    u16 = lambda o: int.from_bytes(data[o:o + 2], "little")  # noqa: E731
    u32 = lambda o: int.from_bytes(data[o:o + 4], "little")  # noqa: E731
    if len(data) < 76 or u32(0) != 0x4C:
        return {}
    flags, pos, out = u32(20), 76, {}
    if flags & 0x01:  # HasLinkTargetIDList
        pos += 2 + u16(pos)
    if flags & 0x02:  # HasLinkInfo: LocalBasePath (ANSI, và Unicode nếu header ≥ 0x24)
        size, header, info_flags = u32(pos), u32(pos + 4), u32(pos + 8)
        if info_flags & 1:
            if header >= 0x24 and u32(pos + 28):
                start = pos + u32(pos + 28)
                end = next((i for i in range(start, min(len(data) - 1, pos + size), 2) if data[i:i + 2] == b"\0\0"), start)
                out["base_path"] = data[start:end].decode("utf-16-le", "replace")
            else:
                start = pos + u32(pos + 16)
                out["base_path"] = data[start:data.find(b"\0", start)].decode("cp1252", "replace")
        pos += size
    unicode = flags & 0x80
    for bit, key in ((0x04, "name"), (0x08, "relative_path"), (0x10, "working_dir"), (0x20, "arguments"),
                     (0x40, "icon")):
        if flags & bit and pos + 2 <= len(data):
            n = u16(pos) * (2 if unicode else 1)
            out[key] = data[pos + 2:pos + 2 + n].decode("utf-16-le" if unicode else "cp1252", "replace")
            pos += 2 + n
    return out


def check_lnk(data: bytes) -> list[Finding]:
    lnk = parse_lnk(data)
    if not lnk:
        return []
    args, out = lnk.get("arguments", ""), []
    targets = [lnk.get("base_path", ""), lnk.get("relative_path", "")]
    lolbin = next((basename(t).lower() for t in targets if basename(t).lower() in LOLBINS), None)
    if lolbin and args.strip():
        out.append(Finding("LNK.LOLBIN", HIGH, "downloader", f"Shortcut chạy {lolbin} kèm tham số",
                           repr(args.strip()[:200])))
    if len(args) - len(args.lstrip()) >= 64 or len(args) > 1024:
        out.append(Finding("LNK.PADDED_ARGS", MEDIUM, "evasion",
                           "Tham số shortcut bị đệm khoảng trắng/quá dài để giấu khỏi hộp thoại Properties",
                           f"{len(args)} ký tự"))
    return out + check_encoded_powershell(" ".join([*targets, args]), "trong shortcut – ")


# --- Dữ liệu mã hóa/nén lạ (không phải định dạng nén/media đã biết) -------------------------------------------

_KNOWN_DENSE = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF", b"wOFF", b"wOF2", b"OggS", b"ID3", b"\xff\xfb",
                b"fLaC", b"\x1aE\xdf\xa3", b"\x28\xb5\x2f\xfd", b"\x04\x22\x4d\x18", b"BZh", b"\x00\x00\x01\x00",
                b"PAR1", b"%PDF", b"icns", b"MSCF", b"ITSF", b"\x93NUMPY", b"\xca\xfe\xba\xbe", b"OTTO", b"\x00\x01\x00\x00")


def check_blob_entropy(data: bytes) -> list[Finding]:
    """File nhị phân không rõ định dạng, gần như ngẫu nhiên hoàn toàn: payload đã mã hóa hoặc nén lạ.
    Chỉ là KHẢ NĂNG (dữ liệu nén/mã hóa hợp pháp cũng vậy) – một mình không gắn cờ."""
    if len(data) < 64 << 10 or data.startswith(_KNOWN_DENSE) or data[4:8] in (b"ftyp", b"moov"):
        return []
    sample = data[:1 << 20] + data[-(1 << 20):] if len(data) > 2 << 20 else data
    e = entropy(sample)
    if e < 7.95:
        return []
    return [Finding("ENTROPY.ENCRYPTED_BLOB", LOW, "evasion",
                    "Dữ liệu không rõ định dạng, entropy gần tối đa – có thể là payload đã mã hóa", f"entropy {e:.3f}")]


# --- Packer (file PE bị nén/mã hóa để giấu mã) ----------------------------------------------

# Tên section đặc trưng → (tên packer, mức độ). UPX hay được dùng hợp pháp nên chỉ LOW;
# các "protector" chống phân tích (Themida, VMProtect…) phổ biến ở mã độc hơn nên MEDIUM.
PACKER_SECTIONS = {
    "upx0": ("UPX", LOW), "upx1": ("UPX", LOW), "upx2": ("UPX", LOW),
    ".aspack": ("ASPack", MEDIUM), ".adata": ("ASPack", MEDIUM),
    ".themida": ("Themida", MEDIUM), ".winlice": ("WinLicense", MEDIUM),
    ".vmp0": ("VMProtect", MEDIUM), ".vmp1": ("VMProtect", MEDIUM), ".vmp2": ("VMProtect", MEDIUM),
    ".mpress1": ("MPRESS", MEDIUM), ".mpress2": ("MPRESS", MEDIUM),
    ".nsp0": ("NsPack", MEDIUM), ".nsp1": ("NsPack", MEDIUM), ".nsp2": ("NsPack", MEDIUM),
    ".enigma1": ("Enigma Protector", MEDIUM), ".enigma2": ("Enigma Protector", MEDIUM),
    "pec2": ("PECompact", MEDIUM), "pec2mo": ("PECompact", MEDIUM), ".petite": ("Petite", MEDIUM),
    "kkrunchy": ("kkrunchy", MEDIUM), ".perplex": ("Perplex", MEDIUM), ".packed": ("RLPack", MEDIUM),
}
HIGH_ENTROPY = 7.2  # mã máy bình thường ~5.5–6.5; dữ liệu nén/mã hóa ~7.5–8
_EXECUTE = 0x20000000  # IMAGE_SCN_MEM_EXECUTE


def entropy(data: bytes) -> float:
    """Entropy Shannon (bit/byte): 0 = toàn một giá trị, 8 = ngẫu nhiên hoàn toàn."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def pe_sections(data: bytes) -> list[tuple[str, int, bytes]]:
    """Đọc bảng section của file PE: [(tên, characteristics, dữ liệu thô)]. Header hỏng → []."""
    try:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            return []
        count, opt_size = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
        table = pe + 24 + opt_size
        sections = []
        for i in range(min(count, 96)):  # PE hợp lệ có tối đa 96 section
            raw = data[table + 40 * i: table + 40 * i + 40]
            if len(raw) < 40:
                break
            name = raw[:8].rstrip(b"\0").decode("latin-1")
            size, offset = struct.unpack_from("<II", raw, 16)
            chars = struct.unpack_from("<I", raw, 36)[0]
            sections.append((name, chars, data[offset:offset + size]))
        return sections
    except struct.error:
        return []


def check_packer(data: bytes) -> list[Finding]:
    sections = pe_sections(data)
    out = []
    names = sorted({PACKER_SECTIONS[n.lower()] for n, _, _ in sections if n.lower() in PACKER_SECTIONS})
    if not names and b"UPX!" in data[:4096]:  # UPX đổi tên section vẫn còn dấu này
        names = [("UPX", LOW)]
    for packer, sev in names:
        out.append(Finding("PACKER.NAME", sev, "evasion", f"File thực thi được nén/bảo vệ bằng {packer}",
                           "packer làm ẩn chuỗi, các luật dò hành vi có thể bỏ sót",
                           confidence="low" if sev == LOW else ""))  # UPX: nhiều công cụ hợp pháp dùng
    hot = [(n or "?", entropy(raw)) for n, chars, raw in sections
           if chars & _EXECUTE and len(raw) >= 4096]
    hot = [(n, e) for n, e in hot if e > HIGH_ENTROPY]
    if hot:
        out.append(Finding("PACKER.ENTROPY", MEDIUM, "evasion",
                           "Vùng mã thực thi có entropy rất cao – mã đã bị nén hoặc mã hóa",
                           ", ".join(f"{n}: {e:.2f}" for n, e in hot)))
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
