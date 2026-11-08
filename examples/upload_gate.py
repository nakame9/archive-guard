"""Cổng kiểm tra file upload mẫu theo integration contract (docs/INTEGRATION.md#tích-hợp-vào-backend).

    python examples/upload_gate.py FILE_UPLOAD THƯ_MỤC_CÁCH_LY THƯ_MỤC_ĐÃ_DUYỆT

Ba quy tắc mà đoạn code này thực thi, không chỉ khuyến nghị:

1. Quét một BẢN SAO trong vùng cách ly do backend sở hữu (tên ngẫu nhiên, chỉ đọc), không quét đường dẫn người dùng
   còn ghi được: người upload không thay được file giữa lúc quét và lúc dùng (TOCTOU).
2. Chỉ disposition "allow" mới được chuyển đi; CHƯA QUÉT ĐỦ (review) không bao giờ được coi là sạch.
3. Chuyển ĐÚNG bản đã quét (os.replace, cùng ổ đĩa, không mở lại file gốc) và đối chiếu SHA-256 với báo cáo.

ArchiveGuard không bảo vệ bước giải nén sau đó: trình giải nén của bạn vẫn phải chống path traversal và giới hạn
dung lượng.
"""
import hashlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

from archive_guard import scan_file


def accept_upload(upload, quarantine, accepted, **scan_options):
    """Trả (đường dẫn trong `accepted` hoặc None, báo cáo). Không bao giờ sửa hay xóa file `upload` gốc."""
    quarantine, accepted = Path(quarantine), Path(accepted)
    fd, tmp = tempfile.mkstemp(dir=quarantine, prefix="upload-")  # tên ngẫu nhiên, quyền 0600
    digest = hashlib.sha256()
    with os.fdopen(fd, "wb") as dst, open(upload, "rb") as src:
        while chunk := src.read(1 << 20):
            digest.update(chunk)
            dst.write(chunk)
    copy = Path(tmp)
    copy.chmod(0o400)  # từ đây không ai trong ứng dụng ghi vào bản đã quét
    report = scan_file(copy, **scan_options)
    if report["disposition"] != "allow":
        return None, report  # để lại trong vùng cách ly cho người xem xét; tự dọn theo chính sách lưu trữ của bạn
    if report["files"][0]["sha256"] != digest.hexdigest():  # báo cáo không phải của bản ta đã chép
        raise RuntimeError("SHA-256 trong báo cáo không khớp bản đã quét")
    final = accepted / copy.name
    os.replace(copy, final)  # cùng ổ đĩa: nguyên tử, không có khoảnh khắc file nằm ở trạng thái nửa vời
    return final, report


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    path, report = accept_upload(*sys.argv[1:], require_sandbox=sys.platform.startswith("linux"),
                                 use_clamav=shutil.which("clamscan") is not None)
    print(f"{report['verdict']} → {report['disposition']}; policy {report['policy']['id']}"
          + (f"; đã chuyển tới {path}" if path else "; giữ trong vùng cách ly"))
    sys.exit(0 if path else 1)
