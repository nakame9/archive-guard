"""Công cụ đo precision/recall/tỷ lệ báo nhầm."""


from helpers import EICAR, FAKE_EXE, make_zip

from archive_guard.scanner import Scanner


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


def test_sample_split_tunes_on_older_and_tests_on_newer():
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("lay_mau", Path(__file__).parent.parent / "benchmark" / "lay_mau.py")
    lay_mau = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lay_mau)
    rows = [{"first_seen": f"2026-10-{d:02d}"} for d in (5, 1, 9, 3, 7, 2)]
    out = lay_mau.chia(rows, 4)  # 4 mẫu mới nhất: 03, 05, 07, 09
    assert [(r["first_seen"][-2:], p) for r, p in out] == [("03", "chinh"), ("05", "chinh"),
                                                           ("07", "kiemtra"), ("09", "kiemtra")]
    assert lay_mau.main(["--auth-key", "x"]) == 2  # thiếu xác nhận máy ảo: từ chối, không gọi mạng


def test_corpus_downloader_resolves_pypi_and_scoped_npm(monkeypatch):
    import importlib.util
    import json
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("tai_bo_sach", Path(__file__).parent.parent / "benchmark" / "tai_bo_sach.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    asked = []

    def fake_get(url):
        asked.append(url)
        if "pypi.org" in url:
            return json.dumps({"urls": [{"filename": "a-1.0.tar.gz", "url": "x"},
                                        {"filename": "a-1.0-py3-none-any.whl", "url": "https://files/a.whl"}]}).encode()
        return json.dumps({"dist": {"tarball": "https://registry/b.tgz"}}).encode()

    monkeypatch.setattr(mod, "_get", fake_get)
    assert mod.file_url("a-1.0-py3-none-any.whl", "pypi:a==1.0") == "https://files/a.whl"
    assert mod.file_url("scope-b-2.0.tgz", "npm:@scope/b@2.0") == "https://registry/b.tgz"
    assert asked == ["https://pypi.org/pypi/a/1.0/json", "https://registry.npmjs.org/@scope%2Fb/2.0"]
