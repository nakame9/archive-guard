# Chính sách bảo mật

## Báo lỗ hổng

Nếu bạn tìm thấy cách khiến ArchiveGuard:

- báo **SẠCH** cho một file mà nó chưa kiểm tra hết, hoặc bỏ qua một lớp phát hiện;
- ghi file ra ngoài thư mục tạm, chạy mã từ file đang quét, hoặc treo/ăn hết RAM bất chấp các giới hạn;
- làm lộ mật khẩu hay nội dung file đang quét,

hãy **báo riêng**, đừng mở issue công khai:
[Security → Report a vulnerability](https://github.com/nakame9/archive-guard/security/advisories/new).

Kèm theo: phiên bản (`archiveguard -V`), hệ điều hành, cách tái hiện. Nếu cần một file để tái hiện, hãy mô tả cách
**tạo** file đó hoặc gửi mã SHA-256, **không gửi mã độc thật**.

## Phạm vi

ArchiveGuard là công cụ hỗ trợ phát hiện, không phải phần mềm diệt virus. Mã độc **không bị phát hiện** là giới hạn
đã biết của heuristic: hãy báo qua issue "Báo nhầm / bỏ sót", không cần báo riêng. `--isolate` là cô lập để ổn
định, không phải sandbox bảo mật (xem [docs/USAGE.md](docs/USAGE.md#chế-độ-cô-lập---isolate)).

## Phiên bản được hỗ trợ

Chỉ phiên bản mới nhất trên nhánh `main` được sửa lỗi bảo mật.
