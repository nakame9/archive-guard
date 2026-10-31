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
