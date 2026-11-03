"""Vận hành: allowlist, --fail-on, file cấu hình + biến môi trường, --stats, --update-db."""
import hashlib
import json

import pytest
from helpers import EICAR, PS_DOWNLOADER, make_zip

from archive_guard.cli import main
from archive_guard.scanner import Scanner


def _sha(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def samples(tmp_path):
    suspicious = make_zip({"setup.ps1": PS_DOWNLOADER})  # công cụ "hai mặt" giả lập: ĐÁNG NGỜ
    (tmp_path / "tool.zip").write_bytes(suspicious)
    (tmp_path / "eicar.zip").write_bytes(make_zip({"eicar.txt": EICAR}))
    (tmp_path / "clean.zip").write_bytes(make_zip({"a.txt": b"hello"}))
    return tmp_path, suspicious


def _allow(tmp_path, *lines):
    f = tmp_path / "allow.txt"
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return f


def test_allowlist_by_archive_hash_suppresses_heuristics(samples):
    tmp_path, data = samples
    allow = _allow(tmp_path, "# công cụ nội bộ đã kiểm duyệt", f"sha256:{_sha(data)} tool v1.2")
    report = Scanner(use_clamav=False, allowlist=[allow]).scan_path(tmp_path / "tool.zip")
    assert report.verdict == "clean"
    inner = report.files[1]
    assert inner.allowlisted == f"sha256:{_sha(data)}" and any(x.rule == "DOWNLOAD.EXEC_PS" for x in inner.suppressed)
    assert "suppressed" in inner.to_dict()  # vẫn ghi lại trong JSON để kiểm toán


def test_allowlist_by_inner_file_hash_covers_only_that_file(tmp_path):
    data = make_zip({"setup.ps1": PS_DOWNLOADER, "other.ps1": PS_DOWNLOADER + b"\n# other"})
    (tmp_path / "a.zip").write_bytes(data)
    report = Scanner(use_clamav=False, allowlist=[_allow(tmp_path, _sha(PS_DOWNLOADER))]).scan_path(tmp_path / "a.zip")
    verdicts = {f.path.split(" > ")[-1]: f.verdict for f in report.files}
    assert verdicts["setup.ps1"] == "clean" and verdicts["other.ps1"] == "suspicious"


def test_allowlist_by_path_on_disk(samples):
    tmp_path, _ = samples
    glob = str(tmp_path.resolve()).replace("\\", "/") + "/tool*.zip"
    report = Scanner(use_clamav=False, allowlist=[_allow(tmp_path, f"path:{glob}")]).scan_path(tmp_path / "tool.zip")
    assert report.verdict == "clean"


def test_allowlist_never_hides_known_malware(samples):
    tmp_path, _ = samples
    eicar_zip = (tmp_path / "eicar.zip").read_bytes()
    allow = _allow(tmp_path, f"sha256:{_sha(eicar_zip)}", f"sha256:{_sha(EICAR)}")
    report = Scanner(use_clamav=False, allowlist=[allow]).scan_path(tmp_path / "eicar.zip")
    assert report.verdict == "malicious"


@pytest.mark.parametrize("line", ["sha256:abc", "md5:" + "0" * 32, "path:", "đường/dẫn/không/có/tiền/tố"])
def test_malformed_allowlist_stops_the_scan(samples, line):
    tmp_path, _ = samples
    with pytest.raises(SystemExit) as e:
        main([str(tmp_path / "tool.zip"), "--no-clamav", "--allowlist", str(_allow(tmp_path, line))])
    assert e.value.code == 2


def test_allowlist_reaches_the_sandboxed_worker(samples):
    tmp_path, data = samples
    out = tmp_path / "r.json"
    code = main([str(tmp_path / "tool.zip"), "--no-clamav", "--json", str(out),
                 "--allowlist", str(_allow(tmp_path, f"sha256:{_sha(data)}"))])
    report = json.loads(out.read_text(encoding="utf-8"))["reports"][0]
    assert code == 0 and report["verdict"] == "clean" and report["files"][1]["allowlisted"]


@pytest.mark.parametrize("target, fail_on, code", [
    ("tool.zip", None, 1), ("tool.zip", "malicious", 0), ("tool.zip", "suspicious", 1),
    ("eicar.zip", "malicious", 2), ("eicar.zip", "incomplete", 0),
])
def test_fail_on(samples, target, fail_on, code):
    tmp_path, _ = samples
    extra = ["--fail-on", fail_on] if fail_on else []
    assert main([str(tmp_path / target), "--no-clamav", "--no-isolate", *extra]) == code


def test_fail_on_rejects_unknown_verdict(samples):
    with pytest.raises(SystemExit):
        main([str(samples[0] / "tool.zip"), "--fail-on", "dangerous"])


def test_config_file_env_and_cli_precedence(samples, monkeypatch):
    tmp_path, _ = samples
    cfg = tmp_path / "archiveguard.toml"
    cfg.write_text('fail-on = ["malicious"]\nno-clamav = true\nno-isolate = true\ntimeout = 120\n', encoding="utf-8")
    target = str(tmp_path / "tool.zip")
    assert main([target, "--config", str(cfg)]) == 0  # file cấu hình: chỉ NGUY HIỂM mới thất bại
    monkeypatch.setenv("ARCHIVEGUARD_FAIL_ON", "suspicious,malicious")
    assert main([target, "--config", str(cfg)]) == 1  # biến môi trường thắng file cấu hình
    assert main([target, "--config", str(cfg), "--fail-on", "malicious"]) == 0  # dòng lệnh thắng tất cả
    monkeypatch.delenv("ARCHIVEGUARD_FAIL_ON")
    monkeypatch.setenv("ARCHIVEGUARD_CONFIG", str(cfg))
    assert main([target]) == 0  # chỉ định file cấu hình bằng biến môi trường


@pytest.mark.parametrize("content", ['tmeout = 5', 'password = "x"', 'timeout = "nhanh"', 'no-clamav = "có"', 'x = ['])
def test_bad_config_is_rejected(samples, content):
    tmp_path, _ = samples
    cfg = tmp_path / "bad.toml"
    cfg.write_text(content, encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        main([str(tmp_path / "tool.zip"), "--config", str(cfg)])
    assert e.value.code == 2


def test_stats_prometheus(samples):
    tmp_path, _ = samples
    stats = tmp_path / "archiveguard.prom"
    code = main([str(tmp_path), "--no-clamav", "--no-isolate", "--stats", str(stats)])
    text = stats.read_text(encoding="utf-8")
    metrics = {line.split(" ")[0]: float(line.split(" ")[1]) for line in text.splitlines() if not line.startswith("#")}
    assert metrics['archiveguard_archives{verdict="malicious"}'] == 1
    assert metrics['archiveguard_archives{verdict="suspicious"}'] == 1
    assert metrics['archiveguard_archives{verdict="clean"}'] == 1
    assert metrics["archiveguard_files"] == 6 and metrics["archiveguard_errors"] == 0
    assert metrics["archiveguard_exit_code"] == code == 2
    assert "# TYPE archiveguard_duration_seconds gauge" in text


def test_update_db_verifies_before_writing(tmp_path):
    from archive_guard import malwarebazaar as mb
    cache = tmp_path / "mb.txt"
    cache.write_text("a" * 64 + " Cu 2026-10-01\n", encoding="utf-8")
    signed = ("# ký\n" + "b" * 64 + " AgentTesla 2026-11-01\n" + "c" * 64 + " Vidar 2026-11-02\n").encode()
    fetched = []

    def fetch(url):
        fetched.append(url)
        return b"bundle" if url.endswith(".sigstore.json") else signed

    def bad_signature(data, bundle):
        raise RuntimeError("chữ ký KHÔNG hợp lệ")

    with pytest.raises(RuntimeError):
        mb.download_db(cache, fetch=fetch, verify=bad_signature)
    assert cache.read_text(encoding="utf-8").startswith("a" * 64)  # chữ ký sai: cache cũ giữ nguyên

    seen = {}
    assert mb.download_db(cache, fetch=fetch, verify=lambda d, b: seen.update(data=d, bundle=b)) == 2
    assert seen == {"data": signed, "bundle": b"bundle"} and cache.read_bytes() == signed
    assert fetched[-2:] == [mb.DB_URL, mb.DB_URL + ".sigstore.json"]


def test_update_db_needs_sigstore_library(monkeypatch):
    import builtins

    from archive_guard import malwarebazaar as mb
    real_import = builtins.__import__

    def no_sigstore(name, *a, **kw):
        if name.startswith("sigstore"):
            raise ImportError(name)
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_sigstore)
    with pytest.raises(RuntimeError, match="archive-guard\\[update\\]"):
        mb._verify_sigstore(b"x", b"{}")
