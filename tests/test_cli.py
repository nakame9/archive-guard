"""Dòng lệnh: mã thoát, hợp đồng JSON (schema_version 1), rules_version."""
import json
import os

import pytest
from helpers import FAKE_EXE, make_zip

from archive_guard.cli import main
from archive_guard.scanner import Scanner


def test_cli_exit_codes_and_json(tmp_path):
    (tmp_path / "clean.zip").write_bytes(make_zip({"a.txt": b"hi"}))
    (tmp_path / "bad.zip").write_bytes(make_zip({"invoice.pdf.exe": FAKE_EXE}))
    out = tmp_path / "report.json"
    assert main([str(tmp_path / "clean.zip"), "--no-clamav"]) == 0
    assert main([str(tmp_path), "--no-clamav", "--json", str(out)]) == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert sorted(r["verdict"] for r in data["reports"]) == ["clean", "suspicious"]
    assert main([str(tmp_path / "khong-ton-tai.zip"), "--no-clamav"]) == 3


def test_skipped_content_is_marked_partial(tmp_path, capsys):
    path = tmp_path / "big.zip"
    path.write_bytes(make_zip({"big.bin": os.urandom(2 << 20)}))
    assert main([str(path), "--no-clamav", "--max-size", "1", "--json", str(tmp_path / "r.json")]) == 4
    assert "KẾT LUẬN: CHƯA QUÉT ĐỦ" in capsys.readouterr().out
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["reports"][0]
    assert report["verdict"] == "incomplete" and report["complete"] is False and report["incomplete"]


def test_cli_unexpected_crash_is_error_not_clean(tmp_path, monkeypatch):
    from archive_guard import scanner as sc

    def crash(self, path):
        raise ValueError("lỗi ngoài dự kiến")

    monkeypatch.setattr(sc.Scanner, "scan_path", crash)
    (tmp_path / "a.zip").write_bytes(make_zip({"a.txt": b"hi"}))
    assert main([str(tmp_path / "a.zip"), "--no-clamav", "--no-isolate"]) == 3


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


@pytest.mark.parametrize("argv", [
    ["--no-isolate", "--worker-memory", "100"],
    ["--no-isolate", "--require-sandbox"],
    ["--no-sandbox", "--require-sandbox"],
])
def test_conflicting_isolation_options_are_rejected(argv):
    with pytest.raises(SystemExit):
        main(["x.zip", *argv])
