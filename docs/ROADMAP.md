# Lộ trình

Cập nhật lần cuối: 2026-11-08 (bản 0.17.1). Giai đoạn hiện tại **chứng minh những gì ArchiveGuard đã tuyên bố**
trước khi thêm tính năng: vá lỗi đã xác nhận, ranh giới tin cậy, toàn vẹn archive, rồi mới tích hợp. Thời gian là ước
lượng, **không** phải cam kết. Muốn góp ý hoặc nhận làm một mục: mở issue và nhắc tên mục.

ArchiveGuard định vị là **chuyên gia kiểm tra file nén** (bổ sung cho antivirus, không thay thế): thế mạnh nằm ở cấu
trúc file nén, giải nén an toàn trong sandbox, và kết luận CHƯA QUÉT ĐỦ thay vì báo sạch bừa
([THREAT_MODEL.md](THREAT_MODEL.md)).

## Đang chờ người giữ repo

| Việc | Vì sao quan trọng |
|---|---|
| Bật **Private vulnerability reporting** (Settings → Code security) | Liên kết báo lỗ hổng riêng tư trong SECURITY.md chỉ hoạt động khi bật – **hiện đang tắt** |
| Thiết lập PyPI Trusted Publisher, ký tag `v0.17.1` → bản phát hành đầu tiên | Người dùng cài được bằng `pip install archive-guard` với attestation PEP 740; các ví dụ trong INTEGRATION.md trỏ tới tag này |
| **Đo recall trên mã độc thật** trong máy ảo (`benchmark/lay_mau.py`) | Con số quan trọng nhất còn thiếu; quyết định thứ tự backlog ở M4 |

## Đóng băng tính năng

Không nhận tính năng mới cho đến khi xong **M2** hoặc hết 6 tuần (tính từ 2026-11-08), tùy điều nào đến trước; hết
hạn thì xem lại, không tự coi mục tiêu đã đạt. Luôn được nhận: sửa lỗi, test, tài liệu, PR xóa bớt code. Bất đồng kỹ
thuật (ngưỡng báo nhầm…) được giải quyết bằng số liệu trên các bộ phần mềm sạch, không bằng tranh luận.

## Milestone

| | Milestone | Việc chính | Xong khi |
|---|---|---|---|
| ✅ | **M0 – Vá lỗi đã xác nhận** (0.17.1) | File nén gắn sau dữ liệu khác, treo ở FIFO, kết quả ClamAV qua worker, hard timeout với `setsid`, lỗi bảng mã ClamAV, trạng thái sandbox macOS | Mỗi lỗi có test hồi quy thất bại trên code cũ |
| ✅ | **M1 – Ranh giới tin cậy** (chưa phát hành) | [THREAT_MODEL.md](THREAT_MODEL.md); kiểm thử đường lỗi (tiêm lỗi vào mọi parser/engine, báo cáo worker không hợp lệ); mã lý do `incomplete_reasons` | Bất biến "bước bắt buộc chưa xong → không SẠCH" được test cho mọi parser và engine |
| | **M2 – Toàn vẹn archive** (tuần 3–6) | Byte coverage cho ZIP (hiểu hết / còn vùng chưa giải thích → ≥ CHƯA QUÉT ĐỦ / mâu thuẫn → ≥ ĐÁNG NGỜ); đọc nội dung entry bị giấu; so sánh `zipfile` với 7-Zip (pin phiên bản), phân loại bất đồng theo hậu quả; evasion corpus có kết quả mong đợi; fuzzing liên tục (ClusterFuzzLite + atheris); bộ phần mềm sạch thứ 4 | Mọi mẫu evasion ≠ SẠCH; tỷ lệ "còn vùng chưa giải thích" trên bộ sạch được công bố và ngưỡng chọn theo đó |
| | **M3 – Tích hợp an toàn** | Hàm thư viện `scan_file()` cô lập mặc định; kết quả có `coverage`, `sandbox`, dấu vân tay policy, evidence, `disposition` gợi ý (không có trường boolean "an toàn"); integration contract; quyết định sandbox Windows (AppContainer hay khuyến nghị Docker/WSL) | Backend mẫu chạy được theo contract; `--require-sandbox` cùng ý nghĩa trên mọi hệ điều hành |
| | **M4 – Bảo trì** | README tiếng Anh; workflow mã băm thôi commit vào `main` (chỉ Release `hash-db` có chữ ký); mở lại backlog bên dưới theo số liệu recall | Phát hành và cập nhật dữ liệu không cần commit tay |

## Backlog (hoãn đến sau M2, thứ tự theo số liệu recall)

| Mục | Ghi chú |
|---|---|
| PDF: JavaScript, `/OpenAction`, `/Launch`, file nhúng | PDF hiện chỉ được dò chuỗi thô |
| Giải nén ISO 9660 / IMG / VHD, OneNote (`.one`) | Hiện chỉ báo CHƯA QUÉT ĐỦ (`UNSUPPORTED_FORMAT`) |
| Luật YARA cho các họ phổ biến chưa có luật (AgentTesla, Formbook, Lumma, XWorm…) | Ứng viên: ReversingLabs (MIT); chỉ đóng gói khi đo báo nhầm đạt |
| Image Docker trên GHCR, ký cosign, kèm SBOM | Hiện phải tự build |
| seccomp cho aarch64 | Chỉ làm khi có người dùng ARM thật |
| sdist tái lập từng bit | Cần đổi build backend; wheel đã tái lập |

## Không nằm trong phạm vi

- Thay thế antivirus/EDR: giám sát thời gian thực, gỡ mã độc.
- Phân tích động (chạy file trong sandbox): ngược nguyên tắc "không bao giờ thực thi nội dung đang quét".
- Dịch vụ chạy liên tục, REST API, dashboard: ArchiveGuard là công cụ dòng lệnh theo lô (số liệu qua `--stats`).
- Plugin phát hiện bằng code của bên thứ ba: mở rộng bằng dữ liệu (luật YARA, danh sách mã băm) là đủ.
- Tự gửi file lên dịch vụ bên ngoài: chỉ tra mã băm, và chỉ khi người dùng bật (`--virustotal`).

## Đã xong gần đây

| Bản | Nội dung |
|---|---|
| chưa phát hành | M1: THREAT_MODEL.md, kiểm thử đường lỗi, `incomplete_reasons`, process chính kiểm tra báo cáo worker, sửa lỗi kiểm tra cấu trúc ZIP bị nuốt thành SẠCH |
| 0.17.1 | M0: file nén gắn sau dữ liệu khác (SFX, byte rác ở đầu), treo ở FIFO, kết quả ClamAV gộp ở process chính, hard timeout với process cháu `setsid`, trạng thái sandbox macOS |
| 0.17.0 | Macro VBA (giải nén mã nguồn), template Office từ xa, LNK, PowerShell mã hóa, cấu trúc ZIP, URLhaus, VirusTotal |
| 0.16.0 | `--update-db` có chữ ký, file cấu hình, `--fail-on`, `--allowlist`, `--stats`; lock file có hash, release ký Sigstore + SBOM |
| 0.15.0 | YARA signature-base (140 file, DRL 1.1), mã băm có ngày (bỏ mẫu > 12 tháng), script lấy mẫu đo recall |

Chi tiết: [CHANGELOG.md](../CHANGELOG.md).
