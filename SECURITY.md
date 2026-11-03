# Chính sách bảo mật

## Báo lỗ hổng

Hãy **báo riêng**, đừng mở issue công khai:
[Security → Report a vulnerability](https://github.com/nakame9/archive-guard/security/advisories/new)
(GitHub Private Vulnerability Reporting: chỉ người giữ repo đọc được, nội dung được GitHub bảo vệ khi truyền và lưu).

Kèm theo: phiên bản (`archiveguard -V`), hệ điều hành, kernel (`uname -r`) nếu liên quan sandbox, cách tái hiện.
Nếu cần một file để tái hiện, hãy mô tả cách **tạo** file đó hoặc gửi mã SHA-256, **không gửi mã độc thật**.

**PGP:** dự án hiện không dùng khóa PGP: kênh báo riêng của GitHub ở trên đã đủ để giữ bí mật nội dung. Nếu bạn bắt
buộc phải dùng PGP, hãy mở một báo cáo riêng ngắn để xin khóa; khóa (nếu có) sẽ được công bố tại đây kèm dấu vân tay.

## Phạm vi

**Là lỗ hổng** (báo riêng):

| Nhóm | Ví dụ |
|---|---|
| Kết luận sai do lỗi xử lý | File chưa được kiểm tra hết mà vẫn ra SẠCH; một lớp phát hiện bị bỏ qua âm thầm; lỗi biến thành SẠCH |
| Parser và cô lập | Chạy mã từ file đang quét; worker crash/treo làm process chính treo; vượt hard timeout, giới hạn CPU/RAM, ngân sách giải nén |
| Sandbox của worker | Đọc/ghi file ngoài phạm vi cho phép, mở kết nối mạng hay Unix socket, ptrace, thoát khỏi Landlock/seccomp/sandbox-exec ở nơi trạng thái báo là đã bật |
| Báo cáo | Trạng thái sandbox báo cao hơn thực tế; chèn ký tự điều khiển terminal qua tên file; JSON bị làm giả từ worker mà process chính không phát hiện được cấu trúc sai |
| Chuỗi cung ứng | Cài được gói/dependency/action/image không khớp hash, digest hay chữ ký đã pin; `--update-db` chấp nhận file không do workflow `update-hashes.yml` ký |
| Bí mật | Lộ mật khẩu file nén, Auth-Key, `VT_API_KEY`, hay nội dung file ra ngoài; allowlist che được "mã độc đã biết" |

**Không phải lỗ hổng** (mở issue công khai):

- Mã độc **không bị phát hiện** hoặc file sạch bị gắn cờ: giới hạn đã biết của heuristic. Dùng mẫu issue
  **"Bỏ sót"** hoặc **"Báo nhầm"**: chúng là dữ liệu để chỉnh luật và đo recall.
- Thiếu sandbox ở nơi tài liệu đã ghi là không có (Windows; seccomp trên ARM; Landlock trên kernel cũ) và trạng thái
  báo đúng là không có. Lớp nào đang bật trên máy nào: [docs/USAGE.md](docs/USAGE.md#cô-lập-và-sandbox-mặc-định).
- Kết luận sai khi **worker đã bị khai thác** (xem mục bên dưới) – trừ khi việc khai thác đó là lỗ hổng mới.
- Lỗ hổng của `unrar`, 7-Zip, ClamAV, Python: báo cho dự án đó; báo cả ở đây nếu ArchiveGuard làm chúng dễ bị khai
  thác hơn.

## Thời gian phản hồi

Dự án do một người giữ, các mốc dưới là cam kết theo khả năng, tính theo ngày làm việc:

| Bước | Mốc |
|---|---|
| Xác nhận đã nhận báo cáo | 3 ngày |
| Đánh giá mức độ, báo lại hướng xử lý | 10 ngày |
| Bản vá cho lỗi nghiêm trọng (chạy mã, thoát sandbox, SẠCH sai có hệ thống) | mục tiêu 30 ngày |
| Công bố | sau khi có bản vá, qua GitHub Security Advisory (kèm CVE nếu phù hợp), ghi công người báo nếu bạn đồng ý |

Nếu quá các mốc trên mà chưa có phản hồi, bạn có thể nhắc lại trong cùng báo cáo.

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

## Cô lập bảo vệ cái gì, không bảo vệ cái gì

Worker và sandbox nhằm **bảo vệ máy của bạn**: nếu một file độc khai thác được lỗi trong bộ giải nén (py7zr, rarfile,
unrar, zlib…), mã của kẻ tấn công bị nhốt trong worker – không ghi ra ngoài thư mục tạm, không đọc file cá nhân
(Linux), không mở kết nối mạng hay Unix socket, không thấy khóa API trong biến môi trường, bị kill khi hết giờ.

Cô lập **không bảo đảm kết luận đúng** khi worker đã bị khai thác: worker bị chiếm quyền có thể trả về một báo cáo
hợp lệ về cấu trúc nhưng nói dối (vd. "SẠCH"). Process chính chỉ kiểm tra được cấu trúc kết quả và lọc ký tự điều
khiển terminal. Với file có thể nhắm vào chính bạn, hãy hiểu SẠCH là "không thấy dấu hiệu", không phải bằng chứng an
toàn, và kết hợp thêm công cụ khác.

## Chuỗi cung ứng của chính ArchiveGuard

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

## Phiên bản được hỗ trợ

Chỉ phiên bản mới nhất trên nhánh `main` được sửa lỗi bảo mật.
