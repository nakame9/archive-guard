"""ArchiveGuard – quét file nén tìm dấu hiệu trojan, keylogger, worm, ransomware…"""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("archive-guard")  # một nguồn duy nhất: `version` trong pyproject.toml
except PackageNotFoundError:  # chạy thẳng từ mã nguồn, chưa `pip install`
    __version__ = "0+unknown"


def scan_file(path, **options):
    """Quét một file trong worker có sandbox, trả báo cáo kèm `disposition`, `policy` – xem archive_guard.api."""
    from .api import scan_file as _scan_file  # nạp muộn: `import archive_guard` (vd. đọc __version__) vẫn nhẹ
    return _scan_file(path, **options)
