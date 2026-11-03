"""Cập nhật mã băm theo họ từ MalwareBazaar (API được giả lập, không gọi mạng)."""
import io
import json

import pytest
from helpers import make_zip, scan

from archive_guard.cli import main


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


def test_update_keeps_dates_and_drops_hashes_older_than_12_months(tmp_path):
    import datetime

    from archive_guard import malwarebazaar
    today = datetime.date(2026, 11, 1)
    old, recent, undated, legacy_seen = "a" * 64, "b" * 64, "c" * 64, "d" * 64
    cache = tmp_path / "mb.txt"
    cache.write_text(f"# cũ\n{old} Vidar 2025-10-01\n{recent} Vidar 2026-06-01\n{undated} njrat\n"
                     f"{legacy_seen} AsyncRAT\n", encoding="utf-8")
    new = "e" * 64

    def fake_query(key, form):
        if form.get("signature") == "AsyncRAT":
            return [{"sha256_hash": legacy_seen, "signature": "AsyncRAT", "first_seen": "2026-09-30 10:00:00"},
                    {"sha256_hash": new, "signature": "AsyncRAT", "first_seen": "2026-10-31 08:00:00"}]
        return []

    assert malwarebazaar.update("k", cache, log=lambda *_: None, query=fake_query, today=today) == (1, 3)
    lines = {line.split()[0]: line.split()[1:] for line in cache.read_text(encoding="utf-8").splitlines()
             if not line.startswith("#")}
    assert lines == {recent: ["Vidar", "2026-06-01"], legacy_seen: ["AsyncRAT", "2026-09-30"],
                     new: ["AsyncRAT", "2026-10-31"]}  # quá 12 tháng và dòng cũ không thấy lại: bị bỏ

    def partly_broken(key, form):
        if form.get("signature") == "Mirai":
            raise RuntimeError("timeout")
        return []

    cache.write_text(f"{undated} njrat\n", encoding="utf-8")
    malwarebazaar.update("k", cache, log=lambda *_: None, query=partly_broken, today=today)
    assert undated in cache.read_text(encoding="utf-8")  # có truy vấn lỗi: chưa biết chắc là cũ, giữ lại


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


def test_urlhaus_payloads_are_a_second_source(monkeypatch):
    from archive_guard import malwarebazaar

    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"], seen["method"], seen["key"] = req.full_url, req.get_method(), req.get_header("Auth-key")
        return io.BytesIO(json.dumps({"query_status": "ok", "payloads": [
            {"sha256_hash": "d" * 64, "signature": None, "firstseen": "2026-11-01 10:00:00"}]}).encode())

    monkeypatch.setattr(malwarebazaar.urllib.request, "urlopen", fake_urlopen)
    rows = malwarebazaar._query("k", {"source": "urlhaus"})
    assert seen == {"url": malwarebazaar.URLHAUS_PAYLOADS, "method": "GET", "key": "k"}
    assert rows[0]["first_seen"].startswith("2026-11-01")
