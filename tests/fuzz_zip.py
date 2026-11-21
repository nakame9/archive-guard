"""Fuzz đường quét ZIP bằng atheris (job `fuzz` trong tests.yml; không phải test của pytest).

Bất biến được kiểm: quét dữ liệu bất kỳ không bao giờ ném lỗi ra ngoài Scanner, và kết luận SẠCH luôn đi kèm
"đã quét trọn vẹn". Hạt giống là evasion corpus (tests/evasion.py).

    python tests/fuzz_zip.py -max_total_time=120 <thư mục hạt giống>
"""
import sys
from pathlib import Path

import atheris

with atheris.instrument_imports(include=["archive_guard"]):
    from archive_guard.scanner import Scanner

SCANNER = Scanner(use_clamav=False, use_yara=False, timeout=5, max_total_mb=64, max_file_mb=16, max_files=2000)


def one_input(data: bytes):
    report = SCANNER.scan_bytes(data, "fuzz.zip").to_dict()
    if report["verdict"] == "clean":
        assert report["complete"], report["incomplete_reasons"]
    for f in report["files"]:
        cov = f.get("coverage")
        if cov and "error" not in cov:
            assert cov["explained"] + cov["unexplained_bytes"] == cov["bytes"], cov


def write_seeds(folder: Path):
    from evasion import CORPUS
    folder.mkdir(parents=True, exist_ok=True)
    for name, (build, *_) in CORPUS.items():
        (folder / name).write_bytes(build())


if __name__ == "__main__":
    seeds = next((Path(a) for a in sys.argv[1:] if not a.startswith("-")), None)
    if seeds and not any(seeds.glob("*")):
        write_seeds(seeds)
    atheris.Setup(sys.argv, one_input)
    atheris.Fuzz()
