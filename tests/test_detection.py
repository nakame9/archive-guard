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
    # evidence: tên chuỗi + offset của lần khớp đầu, không chép nội dung khớp
    detail = next(f for x in report.files for f in x.findings if f.rule == "YARA.Demo").detail
    assert "khớp: $a@0x2" in detail and "hello-malware" not in detail


@pytest.mark.parametrize("score, verdict", [(85, "malicious"), (70, "suspicious")])
def test_community_yara_rule_score_and_author(tmp_path, score, verdict):
    """Luật kiểu signature-base: không có severity/category, có score + author (DRL: phải in tên tác giả)."""
    pytest.importorskip("yara")
    rule = tmp_path / "mal_demo.yar"
    rule.write_text(f'rule MAL_Demo {{ meta: description = "demo" author = "Tác Giả" score = {score} '
                    'strings: $a = "hello-malware" condition: $a and filename != "x" }',  # biến ngoài như THOR
                    encoding="utf-8")
    report = scan(make_zip({"x.bin": b"..hello-malware.."}), yara_paths=[rule])
    hit = [x for f in report.files for x in f.findings if x.rule == "YARA.MAL_Demo"][0]
    assert hit.category == "known_malware" and "Tác Giả" in hit.detail
    assert report.verdict == verdict


def test_bundled_signature_base_rules_compile():
    pytest.importorskip("yara")
    from archive_guard.scanner import DATA_DIR, Scanner
    expected = len(list((DATA_DIR / "rules").rglob("*.yar")))
    status = Scanner(use_clamav=False).engines["yara"]
    assert expected > 100 and status.startswith(f"{expected} file luật; signature-base ") and "Detection Rule" in status


@pytest.mark.parametrize("blob, hit", [
    (b"SystemVirtualVendoredcrates\\ruff_source_file\\src\\lib.rs", False),  # chuỗi ghép của Rust (ruff)
    ("overflowedcrates\\x".encode("utf-16-le"), False),
    (b"\x00DcRat.exe\x00", True),
    (b"[DcRatBuilder] connected", True),  # CamelCase: chữ hoa phía sau vẫn là token mới
    (b"registry\\src\\dcrates.io-index", False),  # chữ thường phía sau: một từ khác (ruff)
    (b"\x00remcos_mutex\x00", True),
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


def test_yara_string_search_matches_the_python_loop():
    from archive_guard import rules
    if not rules._YARA:
        pytest.skip("không có yara-python: chỉ dùng vòng lặp")
    every = sorted(set(rules._LOOKUP.values()))  # mọi chỉ dấu, ASCII lẫn UTF-16, chữ hoa lẫn thường
    blobs = [b"\x00".join(x.upper().encode() for x in every), "|".join(every).encode("utf-16-le"),
             b"Vendoredcrates\\dcrates\x00DcRatBuilder\x00", "overflowedcrates".encode("utf-16-le"),
             "Quasar.Client".encode("utf-16-le") + b"\x00remcos_x", b"x" * 100 + b"GETWINDOWTEXTA"]
    for blob in blobs:
        assert rules._find_strings(blob) == rules._find_strings_loop(blob, rules._LOOKUP)


def test_detection_without_yara_python(monkeypatch):
    from archive_guard import rules
    monkeypatch.setattr(rules, "_YARA", None)  # máy không cài được yara-python: vòng lặp Python
    sample = FAKE_EXE + b"\0GetAsyncKeyState\0https://api.telegram.org/bot1/sendMessage\0\0AsyncRAT\0"
    assert {"KEYLOG.EXFIL", "BACKDOOR.KNOWN_RAT"} <= rules_of(scan(make_zip({"a.exe": sample})))


# --- 0.17: Office, LNK, PowerShell mã hóa, cấu trúc ZIP, entropy ---

def test_vba_decompression_matches_ms_ovba_spec_example():
    """Ví dụ 3.2.2 trong đặc tả MS-OVBA (learn.microsoft.com/openspecs, ms-ovba)."""
    from archive_guard.rules import _ovba_decompress
    compressed = bytes.fromhex("012FB00023616161626364658266007061676869" "6A013808616B6C00206D6E6F70067102700400"
                               "72737475761077787 97A002C".replace(" ", ""))
    assert _ovba_decompress(compressed, 0) == b"#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa"


@pytest.mark.parametrize("source, hit", [
    (b'Sub Document_Open()\r\n  CreateObject("WScript.Shell").Run "cmd /c calc"\r\nEnd Sub', True),
    (b'Sub Workbook_Open()\r\n  Sheets(1).Range("A1").Value = Date\r\nEnd Sub', False),  # macro tự chạy vô hại
    (b'Sub TaoBaoCao()\r\n  Shell "notepad.exe"\r\nEnd Sub', False),  # gọi lệnh nhưng không tự chạy
])
def test_macro_autoexec_needs_both_autorun_and_execution(source, hit):
    from helpers import make_docm
    assert ("DOC.MACRO_AUTOEXEC_EXEC" in rules_of(scan(make_zip({"a.docm": make_docm(source)})))) == hit


def test_external_hyperlink_is_not_a_remote_template():
    rels = (b'<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            b'relationships/hyperlink" Target="https://example.org" TargetMode="External"/></Relationships>')
    docx = make_zip({"word/document.xml": b"<w/>", "word/_rels/document.xml.rels": rels})
    assert "DOC.REMOTE_RESOURCE" not in rules_of(scan(make_zip({"a.docx": docx})))


@pytest.mark.parametrize("target, args, rule", [
    ("C:\\Windows\\System32\\cmd.exe", "/c start http://example.invalid", "LNK.LOLBIN"),
    ("C:\\Program Files\\App\\app.exe", "--profile work", None),  # shortcut bình thường
    ("C:\\Windows\\System32\\cmd.exe", "", None),  # mở cmd không tham số
    ("C:\\Windows\\notepad.exe", " " * 200 + "x", "LNK.PADDED_ARGS"),
])
def test_lnk_heuristics(target, args, rule):
    from helpers import make_lnk
    found = rules_of(scan(make_zip({"a.lnk": make_lnk(target, args)}))) & {"LNK.LOLBIN", "LNK.PADDED_ARGS"}
    assert found == ({rule} if rule else set())


@pytest.mark.parametrize("text, hit", [
    ("powershell.exe -NoP -EncodedCommand {b}", True),
    ("pwsh -e {b}", True),
    ("sed -e {b}", False),  # không phải PowerShell
    ("powershell -enc QUJDREVGR0hJSktMTU5PUA==", False),  # base64 nhưng không phải văn bản UTF-16
])
def test_encoded_powershell_is_decoded(text, hit):
    from helpers import ps_encoded

    from archive_guard.rules import check_encoded_powershell
    found = check_encoded_powershell(text.format(b=ps_encoded("Write-Output 'xin chao'")))
    assert bool(found) == hit


def test_zip_hidden_entry_and_overlap():
    from helpers import zip_with_hidden, zip_with_overlap
    assert "ARCHIVE.HIDDEN_ENTRY" in rules_of(scan(zip_with_hidden({"a.txt": b"a"}, {"b.exe": FAKE_EXE})))
    assert "ARCHIVE.OVERLAP" in rules_of(scan(zip_with_overlap("a.txt", b"A" * 100)))


def test_stored_zip_inside_zip_is_not_a_hidden_entry():
    import io
    import zipfile
    inner = make_zip({"x.txt": b"x"})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:  # local header của ZIP con nằm nguyên trong dữ liệu
        z.writestr("inner.zip", inner)
    assert not rules_of(scan(buf.getvalue())) & {"ARCHIVE.HIDDEN_ENTRY", "ARCHIVE.OVERLAP"}


def test_control_characters_in_names():
    assert "NAME.CONTROL_CHARS" in rules_of(scan(make_zip({"hoa\x07don.txt": b"x"})))


def test_high_entropy_blob_is_only_a_capability():
    import os
    report = scan(make_zip({"data.bin": b"\x00\x01" + os.urandom(200_000), "logo.png": b"\x89PNG" + os.urandom(200_000)}))
    hits = [(f.path, x) for f in report.files for x in f.findings if x.rule == "ENTROPY.ENCRYPTED_BLOB"]
    assert [p for p, _ in hits] == ["sample.zip > data.bin"] and hits[0][1].confidence == "low"
    assert report.verdict == "clean"  # khả năng đơn lẻ không gắn cờ
