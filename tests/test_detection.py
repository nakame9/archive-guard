"""Luật phát hiện: tên file, chuỗi hành vi, packer, YARA và hồi quy cho các lỗi luật đã sửa."""

import pytest
from helpers import EICAR, FAKE_EXE, PS_DOWNLOADER, make_pe, make_zip, rules_of, scan


def test_clean_zip():
    report = scan(make_zip({"readme.txt": b"xin chao", "src/app.py": b"print('hi')"}))
    assert report.verdict == "clean"
    assert not report.incomplete


def test_eicar_inside_nested_zip():
    inner = make_zip({"eicar.com": EICAR})
    report = scan(make_zip({"tools/inner.zip": inner}))
    assert report.verdict == "malicious"
    hit = [f for f in report.files if any(x.rule == "HASH.KNOWN_BAD" for x in f.findings)]
    assert hit[0].path == "sample.zip > tools/inner.zip > eicar.com"


def test_disguised_file_names():
    report = scan(make_zip({"invoice.pdf.exe": FAKE_EXE, "photo\u202egpj.exe": FAKE_EXE,
                            "report.pdf": FAKE_EXE, "scan.jpg            .scr": FAKE_EXE}))
    assert {"NAME.DOUBLE_EXT", "NAME.BIDI", "NAME.CONTENT_MISMATCH", "NAME.PADDING"} <= rules_of(report)
    assert report.verdict != "clean"


def test_zip_slip():
    assert "NAME.PATH_TRAVERSAL" in rules_of(scan(make_zip({"../../evil.bat": b"echo hi"})))


def test_keylogger_indicators():
    sample = (FAKE_EXE + b"SetWindowsHookExA\0GetForegroundWindow\0[BACKSPACE][ENTER][CAPSLOCK]\0"
              + b"https://api.telegram.org/bot123:abc/sendMessage")
    report = scan(make_zip({"svchost.exe": sample}))
    assert report.verdict == "malicious"
    assert {"keylogger", "stealer"} <= set(report.categories)


def test_usb_worm_utf16_strings():
    sample = FAKE_EXE + "autorun.inf".encode("utf-16-le") + b"\0" + "GetDriveTypeW".encode("utf-16-le")
    report = scan(make_zip({"usb.exe": sample, "autorun.inf": b"[autorun]\nopen=usb.exe"}))
    assert {"WORM.USB", "NAME.AUTORUN_INF"} <= rules_of(report)
    assert "worm" in report.categories


def test_powershell_downloader():
    report = scan(make_zip({"setup.ps1": PS_DOWNLOADER}))
    assert "DOWNLOAD.EXEC_PS" in rules_of(report)
    assert report.verdict == "suspicious"


def test_packer_detection():
    import os
    code = (b"\x55\x8b\xec\x83\xec\x10" * 2000)[:8192]  # mã máy lặp lại → entropy thấp
    packed = os.urandom(8192)  # dữ liệu nén/mã hóa → entropy ~8
    exec_flag = 0x60000020
    rules = rules_of(scan(make_pe([(".text", code, exec_flag)]), "app.exe"))
    assert not {r for r in rules if r.startswith("PACKER")}
    upx = rules_of(scan(make_pe([("UPX0", b"", exec_flag), ("UPX1", packed, exec_flag)]), "app.exe"))
    assert {"PACKER.NAME", "PACKER.ENTROPY"} <= upx
    themida = scan(make_pe([(".themida", code, exec_flag)]), "app.exe")
    assert any("Themida" in x.title for f in themida.files for x in f.findings)
    assert "PACKER.ENTROPY" in rules_of(scan(make_pe([(".text", packed, exec_flag)]), "app.exe"))
    assert scan(b"MZ" + bytes(10), "broken.exe").verdict == "clean"  # header hỏng không gây lỗi


def test_payload_in_middle_of_large_file():
    import os

    from archive_guard import rules
    # payload nằm giữa file 48 MB (ngoài vùng 32 MB đầu + 4 MB cuối của bản cũ)
    # và vắt qua ranh giới hai khúc quét 8 MB
    marker = b"vssadmin delete shadows /all /quiet"
    cut = 40 * (1 << 20) - 10
    data = FAKE_EXE + os.urandom(cut - len(FAKE_EXE)) + marker + os.urandom(8 << 20)
    assert cut % rules._CHUNK != 0 and cut // rules._CHUNK != (cut + len(marker)) // rules._CHUNK
    assert "RANSOM.KILL_BACKUP" in rules_of(scan(data, "big.exe"))


def test_custom_yara_rule(tmp_path):
    pytest.importorskip("yara")
    rule = tmp_path / "demo.yar"
    rule.write_text('rule Demo { meta: severity = "critical" category = "trojan" description = "demo" '
                    'strings: $a = "hello-malware" condition: $a }')
    report = scan(make_zip({"x.bin": b"..hello-malware.."}), yara_paths=[rule])
    assert "YARA.Demo" in rules_of(report)
    assert report.verdict == "malicious"


@pytest.mark.parametrize("blob, hit", [
    (b"SystemVirtualVendoredcrates\\ruff_source_file\\src\\lib.rs", False),  # chuỗi ghép của Rust (ruff)
    ("overflowedcrates\\x".encode("utf-16-le"), False),
    (b"\x00DcRat.exe\x00", True),
    (b"[DcRatBuilder] connected", True),  # phía sau tên họ được tự do
    (b"\x00AsyncRAT\x00", True),
    ("Quasar.Client.Config".encode("utf-16-le"), True),
])
def test_family_names_need_word_start(blob, hit):
    found = "BACKDOOR.KNOWN_RAT" in rules_of(scan(make_zip({"a.exe": FAKE_EXE + b"\x00" + blob})))
    assert found == hit


def test_family_name_at_chunk_boundary_keeps_context(monkeypatch):
    from archive_guard import rules
    monkeypatch.setattr(rules, "_CHUNK", 64)
    # "dcrat" bắt đầu đúng ở đầu khúc thứ hai, chữ "e" đứng trước nằm ở khúc thứ nhất → vẫn là báo nhầm
    data = b"x" * (64 - 1) + b"edcrates"
    assert "dcrat" not in rules._find_strings(data)
    assert "dcrat" in rules._find_strings(b"x" * 63 + b" dcrat")


@pytest.mark.parametrize("text, hit", [
    # thư đòi tiền chuộc thật: có lời đòi + cách trả tiền/liên lạc
    (b"All your files have been encrypted! To decrypt your files pay 0.05 Bitcoin. "
     b"Install Tor Browser and open http://abc.onion", True),
    (b"YOUR FILES ARE ENCRYPTED. Send Monero to get the decryptor.", True),
    # chuỗi trong thư viện mạng/TLS (esbuild): không có lời đòi tiền chuộc
    (b"dnsdomaingophertelnetreturn.local.onionip tls: unsupported decryption key type (%T)", False),
    (b"Bitcoin wallet library: export decryption key", False),
])
def test_ransom_note_needs_demand_and_payment(text, hit):
    found = "RANSOM.NOTE" in rules_of(scan(make_zip({"readme.exe": FAKE_EXE + text})))
    assert found == hit
