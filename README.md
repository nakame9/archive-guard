# ArchiveGuard 🛡️

[![tests](https://github.com/nakame9/archive-guard/actions/workflows/tests.yml/badge.svg)](https://github.com/nakame9/archive-guard/actions/workflows/tests.yml)

Công cụ dòng lệnh quét **file nén (ZIP, RAR, 7z, TAR, GZ, BZ2, XZ)** để tìm dấu hiệu mã độc như
**trojan, keylogger, worm, ransomware, stealer, backdoor/RAT, downloader** – trước khi bạn giải nén
hay mở bất cứ thứ gì bên trong.

> ⚠️ ArchiveGuard là công cụ **hỗ trợ phát hiện**, không thay thế phần mềm diệt virus. Kết quả
> "SẠCH" chỉ có nghĩa là không thấy dấu hiệu nguy hiểm, không phải bảo đảm an toàn tuyệt đối.

## Tính năng

- **Không bao giờ giải nén ra đĩa:** mọi thứ được đọc trong bộ nhớ, nên đường dẫn độc kiểu `../../evil.exe`
  (Zip Slip) không ghi đè được gì.
- **Đi vào file nén lồng nhau** (zip trong rar trong 7z…) với một **ngân sách tài nguyên chung** chống archive bomb:
  giải nén theo kiểu streaming, dừng ngay giữa chừng khi vượt giới hạn byte, số entry, độ sâu hay thời gian.
- **Nhiều lớp phát hiện:** tên file giả mạo, nội dung đội lốt, packer (UPX, Themida…), chuỗi hành vi
  (keylogger, tiêm tiến trình, ransomware, đánh cắp dữ liệu…), mã băm mã độc thật từ MalwareBazaar,
  YARA và ClamAV (tùy chọn).
- **Không bao giờ báo SẠCH khi chưa quét hết:** file có mật khẩu, file hỏng, định dạng chưa hỗ trợ, engine lỗi hay
  vượt giới hạn đều cho kết luận `CHƯA QUÉT ĐỦ`.
- **Chế độ cô lập `--isolate`:** mỗi file nén quét trong một process con, có hard timeout và giới hạn RAM.

## Cài đặt

Cần Python 3.10 trở lên.

```bash
git clone https://github.com/nakame9/archive-guard.git
cd archive-guard
pip install -e ".[yara]"    # bỏ [yara] nếu không cần YARA
```

Tùy chọn: `unrar` hoặc 7-Zip trong PATH để đọc nội dung RAR; ClamAV để có thêm engine chữ ký.
Chi tiết: [docs/USAGE.md](docs/USAGE.md#cài-thêm).

## Dùng nhanh

```bash
archiveguard file.zip                       # quét một file
archiveguard Downloads/                     # quét mọi file nén trong thư mục
archiveguard tailieu.rar -p 123456          # thử mật khẩu
archiveguard file.zip --json baocao.json    # xuất báo cáo JSON
archiveguard Downloads/ --isolate           # mỗi file nén quét trong một process con riêng
```

Ví dụ (file mẫu vô hại tạo trong lúc thử nghiệm):

```text
== hoa-don-thang-10.zip ==
  [NGUY HIỂM 100] hoa-don-thang-10.zip > HoaDon_T10.pdf.exe
      HIGH     Trojan / ngụy trang: Đuôi kép giả mạo: trông như .pdf nhưng thực ra là .exe
      HIGH     Keylogger (ghi phím): Chứa nhãn ghi phím đặc trưng của keylogger
               khớp: [backspace], [capslock], [enter]
      MEDIUM   Stealer (đánh cắp dữ liệu): Gửi dữ liệu ra ngoài qua Telegram bot / Discord webhook / SMTP
               khớp: api.telegram.org/bot
  [ĐÁNG NGỜ 30] hoa-don-thang-10.zip > autorun.inf
      MEDIUM   Worm (tự lây lan): autorun.inf – cơ chế tự chạy mà worm USB hay dùng
  Đã quét 4 file: 1 nguy hiểm, 1 đáng ngờ, 0 chưa quét đủ, 2 sạch
  KẾT LUẬN: NGUY HIỂM – dấu hiệu: Keylogger (ghi phím), Stealer (đánh cắp dữ liệu), Trojan / ngụy trang, Worm (tự lây lan)
```

| Kết luận | Mã thoát | Ý nghĩa |
|---|---|---|
| SẠCH | `0` | Đã kiểm tra **toàn bộ** nội dung, không thấy dấu hiệu nguy hiểm |
| ĐÁNG NGỜ | `1` | Có dấu hiệu cần xem lại |
| NGUY HIỂM | `2` | Dấu hiệu mạnh hoặc trùng mã độc đã biết |
| *(lỗi)* | `3` | Không đọc được file, worker crash… |
| CHƯA QUÉT ĐỦ | `4` | Có phần chưa kiểm tra được – **không được coi là sạch** |

## Độ chính xác đã đo

Trên **81 gói phần mềm sạch chưa từng dùng để chỉnh luật** (bản 0.8.0): phần mềm thông dụng bị gắn ĐÁNG NGỜ
**4,2%**, NGUY HIỂM **0%**. **Khả năng phát hiện mã độc thật (recall) chưa được đo.**
Chi tiết và cách tự đo: [docs/BENCHMARK.md](docs/BENCHMARK.md).

## Tài liệu

| Bạn muốn | Đọc |
|---|---|
| Mọi tùy chọn, định dạng JSON, `--isolate`, cập nhật mã băm, giới hạn cần biết | [docs/USAGE.md](docs/USAGE.md) |
| Hiểu code: module, luồng quét, ngân sách, **muốn sửa X thì sửa ở đâu** | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Cách chấm điểm, thêm luật / YARA / mã băm | [docs/RULES.md](docs/RULES.md) |
| Số liệu đo, phương pháp, cách tự đo recall | [docs/BENCHMARK.md](docs/BENCHMARK.md) |
| Đóng góp code, chạy test, quy trình sửa luật | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Báo lỗ hổng bảo mật | [SECURITY.md](SECURITY.md) |
| Lịch sử thay đổi | [CHANGELOG.md](CHANGELOG.md) |

## Giấy phép

[MIT](LICENSE). Công cụ chỉ dùng cho mục đích phòng thủ và học tập.
