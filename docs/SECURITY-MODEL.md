# Mô hình bảo mật

Tài liệu kỹ thuật cho người vận hành và người đánh giá bảo mật: ArchiveGuard bảo vệ gì, tin vào gì, gửi gì ra
ngoài, và làm sao kiểm chứng bản bạn đang chạy. Cách **báo lỗ hổng** và phạm vi: [SECURITY.md](../SECURITY.md).
Các lớp sandbox trên từng hệ điều hành: [USAGE.md](USAGE.md#cô-lập-và-sandbox-mặc-định).

## Cô lập bảo vệ cái gì, không bảo vệ cái gì

Worker và sandbox nhằm **bảo vệ máy của bạn**: nếu một file độc khai thác được lỗi trong bộ giải nén (py7zr, rarfile,
unrar, zlib…), mã của kẻ tấn công bị nhốt trong worker – không ghi ra ngoài thư mục tạm, không đọc file cá nhân
(Linux), không mở kết nối mạng hay Unix socket, không thấy khóa API trong biến môi trường, bị kill khi hết giờ.

Cô lập **không bảo đảm kết luận đúng** khi worker đã bị khai thác: worker bị chiếm quyền có thể trả về một báo cáo
hợp lệ về cấu trúc nhưng nói dối (vd. "SẠCH"). Process chính chỉ kiểm tra được cấu trúc kết quả và lọc ký tự điều
khiển terminal. Với file có thể nhắm vào chính bạn, hãy hiểu SẠCH là "không thấy dấu hiệu", không phải bằng chứng an
toàn, và kết hợp thêm công cụ khác.

## Dữ liệu gửi ra ngoài

Mặc định ArchiveGuard **không gửi gì** ra mạng khi quét. `--virustotal` (tùy chọn) gửi **mã băm SHA-256** của file
thực thi/script/tài liệu tới VirusTotal – không gửi nội dung file; mã băm của một tài liệu nội bộ vẫn cho VirusTotal
biết tài liệu đó tồn tại, nên đừng bật với dữ liệu nhạy cảm. `--update-hashes`/`--update-db` chỉ tải về.

## Cấu hình và allowlist

- File cấu hình chỉ được nạp từ `--config`/`ARCHIVEGUARD_CONFIG`, không tự tìm trong thư mục hiện tại; biến môi
  trường `ARCHIVEGUARD_*` không được chuyển vào worker (worker nhận tùy chọn đã giải quyết qua dòng lệnh).
- Allowlist không bao giờ che phát hiện "mã độc đã biết"; mục `path:` khớp đường dẫn trên đĩa, không khớp tên do
  file nén tự khai. Một cách vượt allowlist khác những điều trên **là** lỗ hổng, hãy báo riêng.
- `--update-db` chỉ chấp nhận chữ ký Sigstore của `.github/workflows/update-hashes.yml@refs/heads/main` trong repo
  này (`malwarebazaar.DB_IDENTITY`).

## Chuỗi cung ứng

| Thành phần | Được pin bằng | Cập nhật |
|---|---|---|
| Thư viện Python | `requirements.txt`, `requirements-dev.txt`: phiên bản + SHA-256 từng file (`pip install --require-hashes`) | Dependabot; CI kiểm tra lock khớp `pyproject.toml` |
| Công cụ build/SBOM/lock | `.github/requirements-tools.txt` (có hash) | Dependabot |
| GitHub Actions | SHA commit (tag có thể bị dời, SHA thì không) | Dependabot |
| Base image Docker | digest `python:3.13-slim@sha256:…` | Dependabot |
| `unrar` trong image | phiên bản + SHA-256, tải từ snapshot.debian.org | Thủ công, xem chú thích trong `Dockerfile` |

`pip-audit` kiểm tra mọi dependency đã pin (cả công cụ release) với cơ sở dữ liệu lỗ hổng mỗi lần push và **mỗi
ngày**: lỗ hổng mới được công bố mà code không đổi vẫn làm CI đỏ.

Build tái lập: wheel build lại từ cùng commit ra **cùng mã băm** (`SOURCE_DATE_EPOCH` = thời điểm commit). sdist và
image Docker chưa tái lập từng bit (setuptools và `pip install` ghi thời điểm build), nhưng mọi thành phần bên trong
đều cố định phiên bản.

## Xác minh bản phát hành

Mỗi bản phát hành (`git tag vX.Y.Z`) được workflow `.github/workflows/release.yml` build trên GitHub Actions, kèm:

- **Provenance SLSA** ký bằng Sigstore, chứng minh file được build từ repo này, đúng commit, đúng workflow:

  ```bash
  gh attestation verify archive_guard-X.Y.Z-py3-none-any.whl --repo nakame9/archive-guard
  ```

- **Chữ ký Sigstore** từng file (`*.sigstore.json` trên GitHub Release):

  ```bash
  python -m pip install sigstore
  python -m sigstore verify identity archive_guard-X.Y.Z-py3-none-any.whl \
    --cert-identity https://github.com/nakame9/archive-guard/.github/workflows/release.yml@refs/tags/vX.Y.Z \
    --cert-oidc-issuer https://token.actions.githubusercontent.com
  ```

- **PyPI**: đăng bằng Trusted Publishing (không có token lâu dài nào để bị lộ) với attestation **PEP 740**, hiện trên
  trang của từng file ở pypi.org.
- **SBOM** CycloneDX (`archive_guard-X.Y.Z.cdx.json`): mọi gói Python được cài cùng ArchiveGuard, kèm phiên bản.
- `SHA256SUMS` cho mọi file của bản phát hành.
- **Tag có chữ ký** của người giữ repo (hiện "Verified" trên GitHub).

## Công cụ bên ngoài có lịch sử lỗ hổng

ArchiveGuard gọi các chương trình C/C++ phân tích chính dữ liệu không tin cậy; lỗ hổng của chúng là lỗ hổng của bạn:

| Công cụ | Ví dụ lỗ hổng đã công bố | Ảnh hưởng tới ArchiveGuard |
|---|---|---|
| `unrar` | CVE-2022-30333 (UnRAR cho Unix trước 6.12): path traversal khi giải nén, bị khai thác để chiếm máy chủ Zimbra. CVE-2025-8088 (WinRAR/UnRAR trên Windows): path traversal, bị khai thác thực tế. | rarfile gọi `unrar p` (in nội dung ra stdout), **không giải nén ra đĩa**, nên lớp lỗi path traversal không áp dụng. Lỗi hỏng bộ nhớ thì bị nhốt trong worker có sandbox. Vẫn cần cập nhật unrar. |
| 7-Zip | CVE-2024-11477: lỗi giải nén Zstandard dẫn tới chạy mã (sửa ở 24.07) | ArchiveGuard đọc 7z bằng py7zr, không gọi 7-Zip; chỉ rarfile có thể dùng `7z` để đọc RAR khi máy không có unrar |
| ClamAV | CVE-2023-20032: tràn bộ đệm trong bộ phân tích HFS+ (có thể chạy mã, sửa tháng 2/2023) | `clamscan` chạy trong worker có sandbox; `clamdscan` chỉ chuyển file descriptor, việc phân tích nằm ở daemon clamd của bạn: hãy cập nhật clamd và chạy nó dưới user riêng |

Nguồn: [CERT-EU 2022-063](https://cert.europa.eu/publications/security-advisories/2022-063/),
[The Hacker News: CVE-2025-8088](https://thehackernews.com/2025/08/winrar-zero-day-under-active.html),
[Debian: CVE-2024-11477](https://security-tracker.debian.org/tracker/CVE-2024-11477),
[CERT-EU 2023-011](https://cert.europa.eu/publications/security-advisories/2023-011/).
