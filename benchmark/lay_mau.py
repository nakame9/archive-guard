"""Lấy mẫu mã độc MỚI từ MalwareBazaar để đo recall – CHỈ chạy trong máy ảo cách ly.

    python benchmark/lay_mau.py --toi-dang-o-may-ao --out mau_doc --moi-ho 10

Mỗi họ trong archive_guard/malwarebazaar.py lấy N mẫu mới nhất (mặc định 10 × 20 họ ≈ 200 mẫu), xuất hiện
SAU ngày --tu-ngay. Mẫu được giữ nguyên dạng ZIP mật khẩu "infected" mà MalwareBazaar trả về (không giải nén, không
chạy). Mỗi họ chia theo thời gian:

    mau_doc/chinh/<Họ>/<sha256>.zip     nửa CŨ hơn  → dùng để chỉnh luật
    mau_doc/kiemtra/<Họ>/<sha256>.zip   nửa MỚI hơn → chỉ dùng để đo, không nhìn khi chỉnh luật

và ghi mau_doc/danh_sach.csv (sha256, họ, first_seen, loại file, phần). Xem docs/BENCHMARK.md, "Cách tự đo recall".
"""
from __future__ import annotations

import argparse
import csv
import datetime
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from archive_guard import malwarebazaar as mb  # noqa: E402


def chia(rows, per_family):
    """N mẫu mới nhất của một họ, chia đôi theo first_seen: (nửa cũ → "chinh", nửa mới → "kiemtra")."""
    rows = sorted(rows, key=lambda r: r["first_seen"])[-per_family:]
    half = len(rows) // 2
    return [(r, "chinh") for r in rows[:half]] + [(r, "kiemtra") for r in rows[half:]]


def _get_file(key, sha256) -> bytes:
    req = urllib.request.Request(mb.API, data=urllib.parse.urlencode({"query": "get_file", "sha256_hash": sha256}).encode(),
                                 headers={"Auth-Key": key, "User-Agent": "archive-guard-benchmark"})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read()
    if not data.startswith(b"PK"):  # lỗi trả về dạng JSON, mẫu trả về dạng ZIP
        raise RuntimeError(data[:200].decode("utf-8", "replace"))
    return data


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--toi-dang-o-may-ao", action="store_true", help="xác nhận đang chạy trong máy ảo cách ly")
    ap.add_argument("--out", type=Path, default=Path("mau_doc"))
    ap.add_argument("--moi-ho", type=int, default=10, help="số mẫu mỗi họ (mặc định 10)")
    ap.add_argument("--tu-ngay", default=None,
                    help="chỉ lấy mẫu first_seen sau ngày này (YYYY-MM-DD); mặc định 30 ngày trước")
    ap.add_argument("--auth-key", default=os.environ.get("ABUSECH_AUTH_KEY", ""))
    ap.add_argument("--thu", action="store_true", help="chỉ liệt kê, không tải")
    args = ap.parse_args(argv)
    if not args.toi_dang_o_may_ao and not args.thu:
        print("Từ chối: chỉ tải mã độc thật trong MÁY ẢO CÁCH LY (không thư mục chia sẻ, không tài khoản cá nhân, "
              "có snapshot). Chạy lại với --toi-dang-o-may-ao nếu đúng là vậy.", file=sys.stderr)
        return 2
    if not args.auth_key:
        print("Thiếu Auth-Key (https://auth.abuse.ch/): đặt ABUSECH_AUTH_KEY hoặc --auth-key", file=sys.stderr)
        return 2
    since = args.tu_ngay or (datetime.date.today() - datetime.timedelta(days=30)).isoformat()
    picked = []
    for family in [f for fams in mb.FAMILIES.values() for f in fams]:
        rows = [r for r in mb._query(args.auth_key, {"query": "get_siginfo", "signature": family, "limit": 1000})
                if str(r.get("first_seen") or "") >= since and len(str(r.get("sha256_hash") or "")) == 64]
        chosen = chia(rows, args.moi_ho)
        print(f"{family}: {len(rows)} mẫu sau {since}, lấy {len(chosen)}")
        picked += [(family, r, part) for r, part in chosen]
        time.sleep(0.5)
    if args.thu:
        return 0
    args.out.mkdir(parents=True, exist_ok=True)
    with open(args.out / "danh_sach.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["sha256", "ho", "first_seen", "loai_file", "phan"])
        for i, (family, r, part) in enumerate(picked, 1):
            sha = r["sha256_hash"].lower()
            dest = args.out / part / family / f"{sha}.zip"
            if not dest.exists():
                try:
                    data = _get_file(args.auth_key, sha)
                except Exception as e:  # một mẫu lỗi không dừng cả lượt
                    print(f"  ! {sha}: {e}", file=sys.stderr)
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                time.sleep(0.5)  # dùng API miễn phí một cách lịch sự
            w.writerow([sha, family, r["first_seen"], r.get("file_type", ""), part])
            print(f"  [{i}/{len(picked)}] {part}/{family}/{sha[:16]}…")
    print(f"Xong. Đo: python -m archive_guard.benchmark --malicious {args.out}/kiemtra -p infected --out ketqua_kiemtra")
    return 0


if __name__ == "__main__":
    sys.exit(main())
