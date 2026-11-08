"""API thư viện (archive_guard.scan_file) và các trường dùng cho tích hợp: disposition, policy."""
import os

import pytest
from helpers import EICAR, make_zip

import archive_guard
from archive_guard import api, isolate


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_scan_file_runs_in_sandboxed_worker_and_returns_decision(tmp_path):
    report = archive_guard.scan_file(_write(tmp_path, "a.zip", make_zip({"a.txt": b"hi"})), use_clamav=False)
    assert report["verdict"] == "clean" and report["disposition"] == "allow"
    assert report["sandbox"] is not None  # đã chạy trong worker, không phải trong process gọi
    assert len(report["policy"]["id"]) == 12 and report["files"][0]["sha256"]


def test_scan_file_rejects_known_malware(tmp_path):
    report = archive_guard.scan_file(_write(tmp_path, "a.zip", make_zip({"eicar.com": EICAR})), use_clamav=False)
    assert report["verdict"] == "malicious" and report["disposition"] == "reject"


def test_scan_file_never_allows_incomplete(tmp_path, monkeypatch):
    monkeypatch.setattr(isolate, "run", lambda *a, **k: (1, "", "boom", False))  # worker crash
    report = archive_guard.scan_file(_write(tmp_path, "a.zip", make_zip({"a.txt": b"hi"})), use_clamav=False)
    assert report["verdict"] == "incomplete" and report["disposition"] == "review"
    assert report["incomplete_reasons"][0]["code"] == "WORKER_ERROR"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="cần FIFO (POSIX)")
def test_scan_file_refuses_non_regular_files(tmp_path):
    os.mkfifo(tmp_path / "f")
    with pytest.raises(FileNotFoundError):
        archive_guard.scan_file(tmp_path / "f")
    with pytest.raises(FileNotFoundError):
        archive_guard.scan_file(tmp_path)


def test_scan_file_rejects_unknown_fail_on(tmp_path):
    with pytest.raises(ValueError):
        archive_guard.scan_file(_write(tmp_path, "a.zip", b"x"), fail_on=("clean",))


@pytest.mark.parametrize("verdict, fail_on, expected", [
    ("clean", api.FAILABLE, "allow"), ("incomplete", api.FAILABLE, "review"),
    ("suspicious", api.FAILABLE, "quarantine"), ("malicious", api.FAILABLE, "reject"),
    ("suspicious", ("malicious",), "allow"),  # policy chỉ chặn NGUY HIỂM: ĐÁNG NGỜ được chấp nhận theo policy đó
])
def test_disposition_follows_policy(verdict, fail_on, expected):
    assert api.disposition(verdict, fail_on) == expected


def test_policy_id_depends_on_content_not_path(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "allow.txt").write_text("path:docs/*\n")
    (b / "allow.txt").write_text("path:docs/*\n")
    same = [api.policy({"fail_on": api.FAILABLE, "allowlist": [d / "allow.txt"]})["id"] for d in (a, b)]
    (b / "allow.txt").write_text("path:*\n")
    changed = api.policy({"fail_on": api.FAILABLE, "allowlist": [b / "allow.txt"]})["id"]
    assert same[0] == same[1] != changed
    assert api.policy({"fail_on": ("malicious",)})["id"] != api.policy({"fail_on": api.FAILABLE})["id"]


# --- Backend mẫu (examples/upload_gate.py): integration contract chạy được ------------------------------------

def _gate():
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location(
        "upload_gate", Path(__file__).parent.parent / "examples" / "upload_gate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.accept_upload


@pytest.mark.parametrize("files, accepted", [({"a.txt": b"hi"}, True), ({"eicar.com": EICAR}, False)])
def test_upload_gate_moves_only_allowed_scanned_copy(tmp_path, files, accepted):
    original = make_zip(files)
    upload = _write(tmp_path, "up.zip", original)
    (tmp_path / "q").mkdir()
    (tmp_path / "ok").mkdir()
    final, report = _gate()(upload, tmp_path / "q", tmp_path / "ok", use_clamav=False)
    assert upload.read_bytes() == original  # file gốc không bị đụng tới
    if accepted:
        assert final.parent == tmp_path / "ok" and final.read_bytes() == original
        assert not list((tmp_path / "q").iterdir())
    else:
        assert final is None and report["disposition"] == "reject"
        assert not list((tmp_path / "ok").iterdir()) and len(list((tmp_path / "q").iterdir())) == 1


def test_upload_gate_never_accepts_incomplete(tmp_path, monkeypatch):
    monkeypatch.setattr(isolate, "run", lambda *a, **k: (1, "", "boom", False))
    (tmp_path / "q").mkdir()
    (tmp_path / "ok").mkdir()
    final, report = _gate()(_write(tmp_path, "up.zip", make_zip({"a.txt": b"hi"})), tmp_path / "q", tmp_path / "ok",
                            use_clamav=False)
    assert final is None and report["disposition"] == "review" and not list((tmp_path / "ok").iterdir())
