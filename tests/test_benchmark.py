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
