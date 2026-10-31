"""Sandbox của worker: trạng thái báo cáo phải khớp với thực tế, và chế độ mặc định không lộ terminal."""
import json
import sys

import pytest
from helpers import make_zip

from archive_guard import sandbox
from archive_guard.cli import main


@pytest.fixture(scope="module")
def probe():
    return sandbox.self_test()


def test_sandbox_status_never_overstates_protection(probe):
    status = probe["status"]
    print("sandbox:", json.dumps(probe, ensure_ascii=False))
    assert probe["ghi_thu_muc_tam"], "worker phải ghi được thư mục tạm riêng"
    if status["filesystem_restricted"]:
        assert not probe["ghi_ngoai_sandbox"], "báo đã giới hạn file nhưng vẫn ghi được ra ngoài"
    if status["filesystem_restricted"] and sys.platform.startswith("linux"):
        assert not probe["doc_file_ca_nhan"], "Landlock bật nhưng vẫn đọc được file ngoài danh sách cho phép"
    if status["network_blocked"]:
        assert not probe["ket_noi_mang"], "báo đã chặn mạng nhưng vẫn kết nối được TCP"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="seccomp chỉ có trên Linux")
def test_seccomp_blocks_ptrace_when_enabled(probe):
    if not probe["status"]["seccomp"].startswith("bật"):
        pytest.skip(probe["status"]["seccomp"])
    assert not probe["ptrace"] and not probe["ket_noi_mang"]


def test_seccomp_program_jumps_stay_in_range():
    prog = sandbox.seccomp_program()
    for i, (code, jt, jf, _) in enumerate(prog):
        if code in (0x15, 0x35):  # lệnh nhảy: đích phải nằm trong chương trình
            assert i + 1 + jt < len(prog) and i + 1 + jf < len(prog)
    assert prog[-1] == (0x06, 0, 0, 0x00050000 | 1)  # lệnh cuối: trả EPERM


def test_require_sandbox_matches_what_the_os_provides(tmp_path, probe):
    (tmp_path / "a.zip").write_bytes(make_zip({"a.txt": b"hi"}))
    out = tmp_path / "r.json"
    code = main([str(tmp_path / "a.zip"), "--no-clamav", "--require-sandbox", "--json", str(out)])
    report = json.loads(out.read_text(encoding="utf-8"))["reports"][0]
    if sandbox.missing(probe["status"]):  # vd. Windows: chưa có sandbox file/mạng → phải từ chối quét
        assert code == 3 and report["verdict"] == "incomplete" and "require-sandbox" in report["worker_error"]
    else:
        assert code == 0 and report["verdict"] == "clean" and report["sandbox"]["filesystem_restricted"]


def test_default_mode_runs_in_a_sandboxed_worker(tmp_path):
    (tmp_path / "a.zip").write_bytes(make_zip({"a.txt": b"hi"}))
    out = tmp_path / "r.json"
    main([str(tmp_path / "a.zip"), "--no-clamav", "--json", str(out)])
    d = json.loads(out.read_text(encoding="utf-8"))
    assert d["isolation"] and d["isolation"]["sandbox"] and d["reports"][0]["sandbox"] is not None


def test_terminal_control_characters_in_file_names_are_escaped(tmp_path, capsys):
    evil = "\x1b[2J\x1b[31mhoadon\u202egpj.exe"  # xóa màn hình + đổi màu + giả mạo đuôi file
    (tmp_path / "a.zip").write_bytes(make_zip({evil: b"MZ" + bytes(64)}))
    main([str(tmp_path / "a.zip"), "--no-clamav", "--no-color"])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\u202e" not in out
    assert "\\u001b[2J" in out and "\\u202e" in out


def test_invalid_worker_result_is_never_clean(tmp_path, monkeypatch):
    from archive_guard import isolate
    monkeypatch.setattr(isolate, "scan", lambda *a, **kw: ({"verdict": "sach-lam"}, "", None, False))
    (tmp_path / "a.zip").write_bytes(make_zip({"a.txt": b"hi"}))
    out = tmp_path / "r.json"
    code = main([str(tmp_path / "a.zip"), "--no-clamav", "--json", str(out)])
    report = json.loads(out.read_text(encoding="utf-8"))["reports"][0]
    assert code == 3 and report["verdict"] == "incomplete" and "không hợp lệ" in report["worker_error"]
