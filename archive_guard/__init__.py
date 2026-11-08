"""ArchiveGuard – quét file nén tìm dấu hiệu trojan, keylogger, worm, ransomware…"""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("archive-guard")  # một nguồn duy nhất: `version` trong pyproject.toml
except PackageNotFoundError:  # chạy thẳng từ mã nguồn, chưa `pip install`
    __version__ = "0+unknown"
