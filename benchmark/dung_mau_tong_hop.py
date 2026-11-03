"""Ghi bộ mẫu dương tính TỔNG HỢP (tests/positives.py, nội dung vô hại) ra thư mục để chạy benchmark.

    python benchmark/dung_mau_tong_hop.py mau_tong_hop/
    python -m archive_guard.benchmark --malicious mau_tong_hop/ --no-clamav --out ketqua_tong_hop
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
from positives import POSITIVES  # noqa: E402

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    for name, (_, build) in POSITIVES.items():
        dest = Path(sys.argv[1]) / name / f"{name}.zip"  # thư mục con = "họ" trong bảng recall theo họ
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(build())
    print(f"Đã ghi {len(POSITIVES)} mẫu vào {sys.argv[1]}")
