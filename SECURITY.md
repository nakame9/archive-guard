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
đã biết của heuristic: hãy báo qua issue "Báo nhầm / bỏ sót", không cần báo riêng.

Cách vượt sandbox của worker (đọc/ghi file ngoài phạm vi cho phép, mở kết nối mạng, thoát khỏi giới hạn CPU/RAM) **là**
lỗ hổng, hãy báo riêng. Lớp nào đang bật trên máy nào: [docs/USAGE.md](docs/USAGE.md#cô-lập-và-sandbox-mặc-định).
Windows chưa có sandbox file/mạng: khi xử lý dữ liệu không tin cậy trên Windows, hãy chạy trong Docker hoặc WSL.

## Cô lập bảo vệ cái gì, không bảo vệ cái gì

Worker và sandbox nhằm **bảo vệ máy của bạn**: nếu một file độc khai thác được lỗi trong bộ giải nén (py7zr, rarfile,
unrar, zlib…), mã của kẻ tấn công bị nhốt trong worker – không ghi ra ngoài thư mục tạm, không đọc file cá nhân
(Linux), không mở kết nối mạng hay Unix socket, không thấy khóa API trong biến môi trường, bị kill khi hết giờ.

Cô lập **không bảo đảm kết luận đúng** khi worker đã bị khai thác: worker bị chiếm quyền có thể trả về một báo cáo
hợp lệ về cấu trúc nhưng nói dối (vd. "SẠCH"). Process chính chỉ kiểm tra được cấu trúc kết quả và lọc ký tự điều
khiển terminal. Với file có thể nhắm vào chính bạn, hãy hiểu SẠCH là "không thấy dấu hiệu", không phải bằng chứng an
toàn, và kết hợp thêm công cụ khác.

## Phiên bản được hỗ trợ

Chỉ phiên bản mới nhất trên nhánh `main` được sửa lỗi bảo mật.
