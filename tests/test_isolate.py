"""--isolate: worker treo/crash/hết RAM không bao giờ cho ra SẠCH; dọn sạch cả cây process."""
import json
import os

import pytest
from helpers import EICAR, FAKE_EXE, make_7z, make_zip

from archive_guard.cli import main


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


def test_worker_does_not_see_secrets_from_parent_environment(tmp_path, monkeypatch):
    import subprocess
    import sys

    from archive_guard import isolate
    monkeypatch.setenv("AG_TEST_SECRET", "bi-mat")
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "khoa-api")
    real_run, seen = isolate.run, {}

    def run_probe(cmd, stdin, timeout, memory_mb=None, cwd=None, env=None):
        # chạy một process thật với ĐÚNG môi trường worker nhận được, hỏi nó thấy biến nào
        probe = [sys.executable, "-c", "import os, sys; sys.stdout.write(repr(sorted(os.environ)))"]
        seen["env"] = subprocess.run(probe, env=env, capture_output=True, text=True).stdout
        return real_run(cmd, stdin, timeout, memory_mb, cwd=cwd, env=env)

    monkeypatch.setattr(isolate, "run", run_probe)
    (tmp_path / "a.zip").write_bytes(make_zip({"a.txt": b"hi"}))
    code, d = _isolated_json(tmp_path, tmp_path / "a.zip")
    assert code == 0 and d["reports"][0]["verdict"] == "clean"  # worker vẫn chạy được với môi trường tối thiểu
    assert "AG_TEST_SECRET" not in seen["env"] and "ABUSECH_AUTH_KEY" not in seen["env"]
    assert "PATH" in seen["env"]


def test_clamdscan_runs_in_parent_and_result_reaches_report(tmp_path, monkeypatch):
    from archive_guard import engines
    from archive_guard.rules import CRITICAL, Finding
    calls = []

    def fake_clamav(path, timeout=900, commands=("clamdscan", "clamscan")):
        calls.append(tuple(commands))
        return [Finding("CLAMAV", CRITICAL, "known_malware", "ClamAV: Test.Sig", str(path), "clamav")]

    monkeypatch.setattr(engines, "clamav_scan", fake_clamav)
    (tmp_path / "a.zip").write_bytes(make_zip({"a.txt": b"hi"}))
    out = tmp_path / "r.json"
    code = main([str(tmp_path / "a.zip"), "--json", str(out)])
    report = json.loads(out.read_text(encoding="utf-8"))["reports"][0]
    assert calls == [("clamdscan",)]  # process cha chỉ gọi clamdscan; worker (process khác) không gọi bản giả này
    assert code == 2 and report["verdict"] == "malicious"
    assert any(x["rule"] == "CLAMAV" for f in report["files"] for x in f["findings"])


def test_compromised_worker_cannot_drop_clamav_result(tmp_path, monkeypatch):
    # worker bị khai thác trả báo cáo SẠCH hợp lệ về cấu trúc: phát hiện của clamdscan (process cha) vẫn phải còn
    from archive_guard import engines, isolate
    from archive_guard.rules import CRITICAL, Finding

    monkeypatch.setattr(engines, "clamav_scan", lambda path, timeout=900, commands=():
                        [Finding("CLAMAV", CRITICAL, "known_malware", "ClamAV: Test.Sig", str(path), "clamav")])
    seen = {}

    def lying_worker(cmd, stdin, timeout, memory_mb=None, cwd=None, env=None):
        seen["request"] = json.loads(stdin)
        clean = {"path": "a.zip", "kind": "zip", "size": 1, "sha256": "", "score": 0, "verdict": "clean",
                 "note": "", "findings": []}
        report = {"target": "a.zip", "verdict": "clean", "categories": [], "complete": True, "incomplete": [],
                  "files": [clean]}
        out = cmd[cmd.index("--json") + 1]
        with open(out, "w", encoding="utf-8") as f:
            json.dump({"reports": [report], "sandbox": None}, f)
        return 0, "", "", False

    monkeypatch.setattr(isolate, "run", lying_worker)
    (tmp_path / "a.zip").write_bytes(make_zip({"a.txt": b"hi"}))
    out = tmp_path / "r.json"
    code = main([str(tmp_path / "a.zip"), "--json", str(out)])
    report = json.loads(out.read_text(encoding="utf-8"))["reports"][0]
    assert "CLAMAV" not in json.dumps(seen["request"])  # kết quả không đi qua worker
    assert code == 2 and report["verdict"] == "malicious"
    assert any(x["rule"] == "CLAMAV" for x in report["files"][0]["findings"])


@pytest.mark.skipif(os.name == "nt", reason="setsid chỉ có trên POSIX; Windows dùng Job Object")
def test_run_returns_when_grandchild_escapes_process_group():
    # process cháu tự setsid (thoát killpg) và giữ stdout: trước 0.17.1 run() chờ EOF của pipe mãi mãi
    import subprocess
    import sys
    import threading

    from archive_guard import isolate
    escape = ("import subprocess, sys; p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'],"
              " start_new_session=True); print(p.pid, flush=True)")
    result = {}
    t = threading.Thread(target=lambda: result.update(r=isolate.run([sys.executable, "-c", escape], b"", 5)),
                         daemon=True)
    t.start()
    t.join(30)
    pid = None
    try:
        assert not t.is_alive(), "run() bị treo vì process cháu giữ pipe"
        pid = int(result["r"][1].split()[0])
    finally:
        if pid is None:  # code cũ: tìm process cháu để dọn
            out = subprocess.run(["pgrep", "-f", "time.sleep(120)"], capture_output=True, text=True).stdout
            pids = [int(x) for x in out.split()]
        else:
            pids = [pid]
        for x in pids:
            try:
                os.kill(x, 9)
            except ProcessLookupError:
                pass
