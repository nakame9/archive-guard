"""Đo độ chính xác của ArchiveGuard trên bộ dữ liệu có nhãn.

    python -m archive_guard.benchmark --malicious mau_doc/ --benign phan_mem_sach/ -p infected --out ketqua

Mỗi file (file nén hoặc file thường) dưới --malicious/--benign là một mẫu. Thư mục con đầu tiên là tên
nhóm: họ mã độc (mau_doc/AgentTesla/x.zip) để tính recall theo họ, hoặc nhóm phần mềm sạch
(phan_mem_sach/thong-dung/, phan_mem_sach/hai-mat/) để tính tỷ lệ báo nhầm theo nhóm.

Kết quả được tách theo lớp phát hiện. Dòng quan trọng nhất là "Không dùng mã băm": nó mô phỏng
mã độc MỚI chưa có trong danh sách mã băm. Mẫu lấy từ MalwareBazaar gần như chắc chắn đã có trong
danh sách, nên dòng "Tất cả" sẽ cao một cách tự nhiên và không nói lên khả năng phát hiện mã độc mới.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
from collections import Counter
from pathlib import Path

from .scanner import Scanner, score_and_verdict

LEVEL = {"clean": 0, "suspicious": 1, "malicious": 2}
# Tên cấu hình → lọc những phát hiện được tính
LAYERS = {
    "Tất cả": lambda f: True,
    "Không dùng mã băm": lambda f: f.engine != "hash",
    "Chỉ heuristic": lambda f: f.engine == "heuristic",
    "Chỉ mã băm": lambda f: f.engine == "hash",
    "Chỉ YARA": lambda f: f.engine == "yara",
    "Chỉ ClamAV": lambda f: f.engine == "clamav",
}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Khoảng tin cậy 95% cho tỷ lệ k/n (Wilson) – vẫn đúng khi k = 0 hoặc n nhỏ."""
    if n == 0:
        return 0.0, 1.0
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return max(0.0, centre - half), min(1.0, centre + half)


def verdict_of(report, keep) -> str:
    """Kết luận của một mẫu nếu chỉ giữ những phát hiện thỏa `keep` (kết luận nặng nhất trong các file con)."""
    return max((score_and_verdict([x for x in f.findings if keep(x)])[1] for f in report.files),
               key=LEVEL.get, default="clean")


def metrics(rows, layer, threshold) -> dict:
    """rows: [{label, verdicts}]; dương tính khi kết luận >= threshold."""
    pos = lambda r: LEVEL[r["verdicts"][layer]] >= LEVEL[threshold]
    tp = sum(1 for r in rows if r["label"] == "malicious" and pos(r))
    fn = sum(1 for r in rows if r["label"] == "malicious" and not pos(r))
    fp = sum(1 for r in rows if r["label"] == "benign" and pos(r))
    tn = sum(1 for r in rows if r["label"] == "benign" and not pos(r))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else None
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall, "f1": f1,
            "recall_ci": wilson(tp, tp + fn) if tp + fn else None,
            "fpr": fp / (fp + tn) if fp + tn else None, "fpr_ci": wilson(fp, fp + tn) if fp + tn else None}


def collect(root: Path, label: str):
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root)
        family = rel.parts[0] if len(rel.parts) > 1 else ""
        yield path, label, family


def run(malicious, benign, scanner: Scanner, log=print) -> dict:
    samples = [*(collect(Path(malicious), "malicious") if malicious else []),
               *(collect(Path(benign), "benign") if benign else [])]
    rows = []
    for i, (path, label, family) in enumerate(samples, 1):
        t = time.time()
        try:
            report = scanner.scan_path(path)
        except OSError as e:
            log(f"  ! bỏ qua {path}: {e}")
            continue
        rows.append({
            "path": str(path), "label": label, "family": family, "seconds": round(time.time() - t, 2),
            "complete": not report.incomplete,
            "verdicts": {name: verdict_of(report, keep) for name, keep in LAYERS.items()},
            "rules": sorted({x.rule for f in report.files for x in f.findings if f.verdict != "clean"}),
            "files_scanned": len(report.files),
        })
        log(f"  [{i}/{len(samples)}] {label:<9} {rows[-1]['verdicts']['Tất cả']:<10} {path.name}")
    active = [n for n in LAYERS if any(LEVEL[r["verdicts"][n]] for r in rows) or n in
              ("Tất cả", "Không dùng mã băm", "Chỉ heuristic")]
    result = {"engines": scanner.engines, "samples": len(rows),
              "malicious": sum(r["label"] == "malicious" for r in rows),
              "benign": sum(r["label"] == "benign" for r in rows),
              "incomplete": sum(not r["complete"] for r in rows),
              "metrics": {t: {n: metrics(rows, n, t) for n in active} for t in ("suspicious", "malicious")},
              "rows": rows}
    families = sorted({r["family"] for r in rows if r["family"] and r["label"] == "malicious"})
    result["per_family"] = {
        fam: {n: metrics([r for r in rows if r["family"] == fam], n, "suspicious")["recall"]
              for n in ("Tất cả", "Không dùng mã băm")} | {"n": sum(r["family"] == fam for r in rows)}
        for fam in families}
    result["per_benign_group"] = {
        g: {t: metrics([r for r in rows if r["label"] == "benign" and r["family"] == g], "Tất cả", t)["fpr"]
            for t in ("suspicious", "malicious")} | {"n": sum(r["label"] == "benign" and r["family"] == g for r in rows)}
        for g in sorted({r["family"] for r in rows if r["label"] == "benign"})}
    # Luật nào gây báo nhầm / luật nào bắt được mẫu độc mà không cần mã băm → dữ liệu để tinh chỉnh
    result["fp_rules"] = Counter(x for r in rows if r["label"] == "benign"
                                 and r["verdicts"]["Tất cả"] != "clean" for x in r["rules"]).most_common()
    result["tp_rules_without_hash"] = Counter(
        x for r in rows if r["label"] == "malicious" and r["verdicts"]["Không dùng mã băm"] != "clean"
        for x in r["rules"] if not x.startswith("HASH")).most_common()
    return result


def _pct(x, ci=None):
    if x is None:
        return "–"
    return f"{x:.1%}" + (f" ({ci[0]:.1%}–{ci[1]:.1%})" if ci else "")


def to_markdown(res: dict) -> str:
    out = [f"Mẫu: {res['samples']} ({res['malicious']} độc, {res['benign']} sạch); "
           f"quét chưa đầy đủ: {res['incomplete']}", ""]
    for t, title in (("suspicious", "Dương tính khi kết luận ≥ ĐÁNG NGỜ"),
                     ("malicious", "Dương tính khi kết luận = NGUY HIỂM")):
        out += [f"### {title}", "",
                "| Lớp | TP | FN | FP | TN | Precision | Recall (KTC 95%) | F1 | Tỷ lệ báo nhầm (KTC 95%) |",
                "|---|---|---|---|---|---|---|---|---|"]
        for name, m in res["metrics"][t].items():
            out.append(f"| {name} | {m['tp']} | {m['fn']} | {m['fp']} | {m['tn']} | {_pct(m['precision'])} | "
                       f"{_pct(m['recall'], m['recall_ci'])} | {_pct(m['f1'])} | {_pct(m['fpr'], m['fpr_ci'])} |")
        out.append("")
    if res["per_family"]:
        out += ["### Recall theo họ (≥ ĐÁNG NGỜ)", "", "| Họ | Số mẫu | Tất cả | Không dùng mã băm |",
                "|---|---|---|---|"]
        out += [f"| {fam} | {v['n']} | {_pct(v['Tất cả'])} | {_pct(v['Không dùng mã băm'])} |"
                for fam, v in res["per_family"].items()]
        out.append("")
    if len(res["per_benign_group"]) > 1:
        out += ["### Tỷ lệ báo nhầm theo nhóm phần mềm sạch (lớp Tất cả)", "",
                "| Nhóm | Số mẫu | ≥ ĐÁNG NGỜ | = NGUY HIỂM |", "|---|---|---|---|"]
        out += [f"| {g or '(gốc)'} | {v['n']} | {_pct(v['suspicious'])} | {_pct(v['malicious'])} |"
                for g, v in res["per_benign_group"].items()]
        out.append("")
    fps = [r for r in res["rows"] if r["label"] == "benign" and r["verdicts"]["Tất cả"] != "clean"]
    fns = [r for r in res["rows"] if r["label"] == "malicious" and r["verdicts"]["Không dùng mã băm"] == "clean"]
    out += ["### Báo nhầm (mẫu sạch bị gắn cờ)", ""]
    out += [f"- `{Path(r['path']).name}` ({r['family'] or '?'}) → {r['verdicts']['Tất cả']}: {', '.join(r['rules'])}"
            for r in fps] or ["- Không có"]
    out += ["", "### Bỏ sót khi không dùng mã băm (mẫu độc bị coi là sạch)", ""]
    out += [f"- `{Path(r['path']).name}` ({r['family'] or '?'})" for r in fns[:50]] or ["- Không có"]
    if len(fns) > 50:
        out.append(f"- … và {len(fns) - 50} mẫu khác (xem file JSON)")
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m archive_guard.benchmark", description=__doc__.split("\n\n")[0])
    ap.add_argument("--malicious", type=Path, help="thư mục mẫu độc (thư mục con = tên họ)")
    ap.add_argument("--benign", type=Path, help="thư mục mẫu sạch")
    ap.add_argument("-p", "--password", action="append", default=[], help="mật khẩu file nén (MalwareBazaar: infected)")
    ap.add_argument("--out", type=Path, default=Path("benchmark"), help="tiền tố file kết quả (.json, .md)")
    ap.add_argument("--no-clamav", action="store_true")
    args = ap.parse_args(argv)
    if not args.malicious and not args.benign:
        ap.error("cần ít nhất --malicious hoặc --benign")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    scanner = Scanner(passwords=args.password, use_clamav=not args.no_clamav)
    print("Engine:", scanner.engines)
    res = run(args.malicious, args.benign, scanner)
    md = to_markdown(res)
    args.out.with_suffix(".json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    args.out.with_suffix(".md").write_text(md, encoding="utf-8")
    print("\n" + md + f"\nĐã ghi {args.out.with_suffix('.md')} và {args.out.with_suffix('.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
