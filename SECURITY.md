# Chính sách bảo mật

## Phiên bản được hỗ trợ

Chỉ **bản phát hành mới nhất** và nhánh `main` được vá lỗi bảo mật; bản cũ hơn không được backport.
Kiểm tra phiên bản: `archiveguard -V`. Danh sách bản phát hành: [Releases](https://github.com/nakame9/archive-guard/releases).

## Báo lỗ hổng

**Báo riêng, đừng mở issue công khai:**
[Security → Report a vulnerability](https://github.com/nakame9/archive-guard/security/advisories/new)
(GitHub Private Vulnerability Reporting – chỉ người giữ repo đọc được).

Kèm theo:

- phiên bản (`archiveguard -V`), hệ điều hành, kernel (`uname -r`) nếu liên quan sandbox;
- cách tái hiện; nếu cần một file, hãy mô tả cách **tạo** file đó hoặc ghi SHA-256 – **không gửi mã độc thật**.

**PGP:** dự án không dùng khóa PGP; kênh báo riêng của GitHub ở trên đã giữ bí mật nội dung. Nếu bắt buộc phải dùng
PGP, hãy mở một báo cáo riêng ngắn để xin khóa; khóa (nếu có) sẽ được công bố tại đây kèm dấu vân tay.

## Phạm vi

**Là lỗ hổng** – báo riêng:

| Nhóm | Ví dụ |
|---|---|
| Kết luận sai do lỗi xử lý | File chưa được kiểm tra hết mà vẫn ra SẠCH; một lớp phát hiện bị bỏ qua âm thầm |
| Parser và cô lập | Chạy mã từ file đang quét; worker làm process chính treo; vượt hard timeout, giới hạn CPU/RAM hay ngân sách giải nén |
| Sandbox | Đọc/ghi file ngoài phạm vi cho phép, mở kết nối mạng hay Unix socket, thoát Landlock/seccomp/sandbox-exec ở nơi trạng thái báo là đã bật |
| Báo cáo | Trạng thái sandbox báo cao hơn thực tế; chèn ký tự điều khiển terminal qua tên file |
| Chuỗi cung ứng | Cài được gói/action/image không khớp hash, digest hay chữ ký đã pin; `--update-db` chấp nhận file không do workflow `update-hashes.yml` ký |
| Bí mật và allowlist | Lộ mật khẩu file nén, Auth-Key, `VT_API_KEY` hay nội dung file; allowlist che được "mã độc đã biết" |

**Không phải lỗ hổng** – mở issue công khai:

- Mã độc không bị phát hiện, file sạch bị gắn cờ: dùng mẫu issue **"Bỏ sót"** / **"Báo nhầm"**.
- Thiếu sandbox ở nơi tài liệu đã ghi là không có (Windows, seccomp trên ARM, Landlock trên kernel cũ) và trạng thái
  báo đúng điều đó.
- Kết luận sai khi worker **đã** bị khai thác – trừ khi cách khai thác là lỗ hổng mới
  ([giới hạn của cô lập](docs/SECURITY-MODEL.md#cô-lập-bảo-vệ-cái-gì-không-bảo-vệ-cái-gì)).
- Lỗ hổng của `unrar`, 7-Zip, ClamAV, Python: báo cho dự án đó; báo cả ở đây nếu ArchiveGuard làm chúng dễ bị khai
  thác hơn.

## Thời gian phản hồi

Dự án do một người giữ; các mốc là cam kết theo khả năng, tính theo ngày làm việc.

| Bước | Mốc |
|---|---|
| Xác nhận đã nhận báo cáo | 3 ngày |
| Đánh giá mức độ, báo lại hướng xử lý | 10 ngày |
| Bản vá cho lỗi nghiêm trọng (chạy mã, thoát sandbox, SẠCH sai có hệ thống) | mục tiêu 30 ngày |
| Công bố | Sau khi có bản vá, qua GitHub Security Advisory (kèm CVE nếu phù hợp); ghi công người báo nếu bạn đồng ý |

Quá các mốc trên mà chưa có phản hồi: nhắc lại trong cùng báo cáo.

## Tài liệu liên quan

- [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md): cô lập bảo vệ gì, dữ liệu gửi ra ngoài, chuỗi cung ứng,
  **cách xác minh bản phát hành**, lịch sử CVE của công cụ bên ngoài.
- [docs/USAGE.md](docs/USAGE.md#cô-lập-và-sandbox-mặc-định): lớp sandbox nào có trên hệ điều hành nào.
