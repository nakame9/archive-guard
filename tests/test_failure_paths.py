"""Kiểm thử đường lỗi: bất kỳ bước bắt buộc nào không hoàn tất thì kết luận KHÔNG BAO GIỜ là SẠCH.

Ba nhóm (docs/THREAT_MODEL.md):
1. Tiêm exception vào từng parser (ZIP, TAR, 7z, RAR), kiểm tra cấu trúc ZIP và từng engine (heuristic, YARA, ClamAV),
   ở đầu và giữa chừng, với nhiều loại lỗi khác nhau.
2. Lỗi process của worker (crash, bị kill, treo, process cháu thoát khỏi nhóm): test_isolate.py.
3. Toàn vẹn kết quả: worker trả JSON cụt, sai cấu trúc, mâu thuẫn → lỗi, không bao giờ SẠCH.
"""
import json
import struct
import zlib

import pytest
from helpers import make_7z, make_zip, tar_gz

from archive_guard import engines, extract, isolate, rules
from archive_guard.cli import main
from archive_guard.scanner import REASONS

ERRORS = [ValueError("x"), OSError(5, "io"), RuntimeError("x"), MemoryError(), KeyError("x"), struct.error("x"),
          zlib.error("x"), EOFError(), RecursionError(), NotImplementedError()]
ERROR_IDS = [type(e).__name__ for e in ERRORS]

ARCHIVES = {  # loại → (tên hàm đọc trong extract, dữ liệu mẫu có 2 file con)
    "zip": ("_zip", lambda: make_zip({"a.txt": b"a", "b.txt": b"b"})),
    "tar": ("_tar", lambda: tar_gz({"a.txt": b"a", "b.txt": b"b"})),
    "7z": ("_7z", lambda: make_7z({"a.txt": b"a", "b.txt": b"b"})),
    "rar": ("_rar", lambda: b"Rar!\x1a\x07\x01\x00" + bytes(64)),  # hàm đọc bị thay, chỉ cần magic đúng
}


def _scan(tmp_path, data, *extra):
    """Chạy CLI trong process (để monkeypatch có hiệu lực); trả (mã thoát, báo cáo hoặc None)."""
    target = tmp_path / "sample.bin"
    target.write_bytes(data)
    out = tmp_path / "r.json"
    code = main([str(target), "--no-isolate", "--no-clamav", "--json", str(out), *extra])
    reports = json.loads(out.read_text(encoding="utf-8"))["reports"] if out.exists() else []
    return code, (reports[0] if reports else None)


def _assert_never_clean(code, report):
    assert code != 0, "bước bắt buộc lỗi nhưng lệnh vẫn thành công (SẠCH)"
    if report is not None:  # mã 3 = lỗi, có thể không có báo cáo
        assert report["verdict"] != "clean"
        if report["verdict"] == "incomplete":
            reasons = report["incomplete_reasons"]
            assert reasons and len(reasons) == len(report["incomplete"])
            assert {r["code"] for r in reasons} <= set(REASONS)


def _failing_reader(original, exc, after):
    """Bọc hàm đọc file nén: trả `after` file con thật rồi ném exc (after=0: lỗi ngay từ đầu)."""
    def reader(*args, **kw):
        for i, member in enumerate(original(*args, **kw)):
            if i == after:
                raise exc
            yield member
        raise exc  # file nén có ít file con hơn `after`: vẫn lỗi ở cuối
    return reader


@pytest.mark.parametrize("exc", ERRORS, ids=ERROR_IDS)
@pytest.mark.parametrize("after", [0, 1], ids=["dau", "giua-chung"])
@pytest.mark.parametrize("kind", sorted(ARCHIVES))
def test_parser_failure_is_never_clean(tmp_path, monkeypatch, kind, after, exc):
    func, make = ARCHIVES[kind]
    data = make()
    original = getattr(extract, func)
    if kind == "rar":  # không cần unrar thật: hàm đọc giả trả hai file con rồi lỗi
        def original(*a, **kw):
            yield extract.Member("a.txt", b"a", 1)
            yield extract.Member("b.txt", b"b", 1)
    monkeypatch.setattr(extract, func, _failing_reader(original, exc, after))
    code, report = _scan(tmp_path, data)
    _assert_never_clean(code, report)
    assert code == 4 and "ARCHIVE_UNREADABLE" in {r["code"] for r in report["incomplete_reasons"]}


@pytest.mark.parametrize("exc", ERRORS, ids=ERROR_IDS)
def test_zip_structure_check_failure_is_never_clean(tmp_path, monkeypatch, exc):
    # trước M1: lỗi ở bước kiểm tra entry giấu/vùng chồng nhau bị nuốt im lặng → SẠCH dù chưa kiểm tra
    def boom(src):
        raise exc
    monkeypatch.setattr("archive_guard.scanner.zip_anomalies", boom)
    code, report = _scan(tmp_path, make_zip({"a.txt": b"a"}))
    _assert_never_clean(code, report)
    assert "STRUCTURE_UNCHECKED" in {r["code"] for r in report["incomplete_reasons"]}


@pytest.mark.parametrize("exc", ERRORS, ids=ERROR_IDS)
@pytest.mark.parametrize("target", ["heuristic", "yara"])
def test_engine_failure_is_never_clean(tmp_path, monkeypatch, target, exc):
    def boom(*a, **kw):
        raise exc
    if target == "heuristic":
        monkeypatch.setattr(rules, "check_content", boom)
    else:
        monkeypatch.setattr(engines, "yara_scan", boom)
    code, report = _scan(tmp_path, make_zip({"a.txt": b"a"}))
    _assert_never_clean(code, report)
    assert "ENGINE_ERROR" in {r["code"] for r in report["incomplete_reasons"]}


@pytest.mark.parametrize("behaviour", ["exception", "unavailable"])
def test_clamav_failure_is_never_clean(tmp_path, monkeypatch, behaviour):
    def clamav(path, timeout=900, commands=()):
        if behaviour == "exception":
            raise RuntimeError("clamav hỏng")
        return None  # không chạy được / hết giờ
    monkeypatch.setattr(engines, "find_clamav", lambda: "clamscan")
    monkeypatch.setattr(engines, "clamav_scan", clamav)
    target = tmp_path / "a.zip"
    target.write_bytes(make_zip({"a.txt": b"a"}))
    out = tmp_path / "r.json"
    code = main([str(target), "--no-isolate", "--json", str(out)])
    reports = json.loads(out.read_text(encoding="utf-8"))["reports"]
    _assert_never_clean(code, reports[0] if reports else None)
    if behaviour == "unavailable":
        assert code == 4 and reports[0]["incomplete_reasons"][0]["code"] == "CLAMAV_UNAVAILABLE"
    else:
        assert code == 3  # lỗi ngoài dự kiến: mã 3, không bao giờ để lọt thành SẠCH


# --- Toàn vẹn kết quả: worker trả về thứ process chính không tin được -------------------------------------------

def _clean_report(**changes):
    file = {"path": "a.zip", "kind": "zip", "size": 1, "sha256": "", "score": 0, "verdict": "clean", "note": "",
            "findings": []}
    report = {"target": "a.zip", "verdict": "clean", "categories": [], "complete": True, "incomplete": [],
              "incomplete_reasons": [], "files": [file]}
    report.update(changes)
    return {"reports": [report], "sandbox": None}


@pytest.mark.parametrize("payload", [
    '{"reports": [{"verdict": "clean"',                                    # bị kill giữa lúc ghi
    json.dumps({"reports": []}),                                           # không có báo cáo
    json.dumps({"reports": [_clean_report()["reports"][0]] * 2}),          # hai báo cáo cho một file
    json.dumps([1, 2, 3]),                                                 # sai kiểu hoàn toàn
    json.dumps(_clean_report(files=[])),                                   # SẠCH mà không quét file nào
    json.dumps(_clean_report(files="a.zip")),                              # sai kiểu trường
    json.dumps({"reports": [{"verdict": "clean"}]}),                       # thiếu trường
    json.dumps(_clean_report(incomplete=["a.zip: lỗi"])),                  # mâu thuẫn: còn phần chưa quét mà SẠCH
], ids=["cut", "rong", "hai-bao-cao", "sai-kieu", "khong-file", "files-sai-kieu", "thieu-truong", "mau-thuan"])
def test_untrustworthy_worker_result_is_never_clean(tmp_path, monkeypatch, payload):
    def worker(cmd, stdin, timeout, memory_mb=None, cwd=None, env=None):
        with open(cmd[cmd.index("--json") + 1], "w", encoding="utf-8") as f:
            f.write(payload)
        return 0, "", "", False
    monkeypatch.setattr(isolate, "run", worker)
    target = tmp_path / "a.zip"
    target.write_bytes(make_zip({"a.txt": b"a"}))
    out = tmp_path / "r.json"
    code = main([str(target), "--no-clamav", "--json", str(out)])
    report = json.loads(out.read_text(encoding="utf-8"))["reports"][0]
    assert code == 3 and report["verdict"] == "incomplete"
    assert report["incomplete_reasons"][0]["code"] == "WORKER_ERROR"


def test_well_formed_worker_result_is_accepted(tmp_path, monkeypatch):
    # đối chứng cho test trên: báo cáo hợp lệ thì được nhận nguyên vẹn
    def worker(cmd, stdin, timeout, memory_mb=None, cwd=None, env=None):
        with open(cmd[cmd.index("--json") + 1], "w", encoding="utf-8") as f:
            json.dump(_clean_report(), f)
        return 0, "", "", False
    monkeypatch.setattr(isolate, "run", worker)
    target = tmp_path / "a.zip"
    target.write_bytes(make_zip({"a.txt": b"a"}))
    assert main([str(target), "--no-clamav"]) == 0
