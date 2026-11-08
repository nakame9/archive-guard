# Lộ trình

Cập nhật lần cuối: 2026-11-08 (bản 0.17.1). Thứ tự dưới đây là thứ tự ưu tiên, **không** phải cam kết ngày.
Muốn góp ý hoặc nhận làm một mục: mở issue (mẫu "Lỗi" hoặc thảo luận trong issue sẵn có) và nhắc tên mục.

## Đang chờ người giữ repo

| Việc | Vì sao quan trọng |
|---|---|
| Bật **Private vulnerability reporting** (Settings → Code security) | Liên kết báo lỗ hổng riêng tư trong SECURITY.md chỉ hoạt động khi bật |
| Thiết lập PyPI Trusted Publisher, ký tag `v0.17.1` → bản phát hành đầu tiên | Người dùng cài được bằng `pip install archive-guard` với attestation PEP 740 |
| **Đo recall trên mã độc thật** trong máy ảo (`benchmark/lay_mau.py`) | Con số quan trọng nhất còn thiếu; mọi luật sau này nên được chọn theo kết quả đó |

## Tiếp theo

| # | Mục | Ghi chú |
|---|---|---|
| 1 | Chỉnh luật theo kết quả recall (phần `chinh/`), công bố phần `kiemtra/` | Theo kỷ luật trong docs/BENCHMARK.md |
| 2 | Quét **nội dung** các entry ZIP bị giấu khỏi danh mục | Hiện chỉ báo `ARCHIVE.HIDDEN_ENTRY`, chưa đọc dữ liệu của chúng |
| 3 | PDF: JavaScript, `/OpenAction`, `/Launch`, file nhúng | PDF hiện chỉ được dò chuỗi thô |
| 4 | Giải nén ISO 9660 / IMG / VHD, OneNote (`.one`) | Hiện chỉ cảnh báo theo đuôi file và báo CHƯA QUÉT ĐỦ |
| 5 | Phát hành image Docker lên GHCR, ký bằng cosign, kèm SBOM | Hiện phải tự build |
| 6 | Sandbox trên Windows (AppContainer hoặc restricted token) | Windows hiện chỉ có cô lập process |
| 7 | seccomp cho aarch64 | Chỉ làm khi có người dùng ARM thật; CI đã có runner arm64 để kiểm chứng |
| 8 | Bộ luật YARA cho các họ phổ biến chưa có luật (AgentTesla, Formbook, Lumma, XWorm…) | Ứng viên: ReversingLabs (MIT). Chỉ đóng gói khi đo báo nhầm đạt như vòng 4 |
| 9 | sdist tái lập từng bit | Cần đổi build backend; wheel đã tái lập |
| 10 | Bộ kiểm tra báo nhầm thứ 4, thêm phần mềm người dùng phổ thông (game, bộ cài, tài liệu Office/PDF) | Ba bộ hiện có chỉ gồm gói PyPI/npm |

## Không nằm trong phạm vi

- Thay thế antivirus/EDR: giám sát thời gian thực, gỡ mã độc, phân tích động (chạy file trong sandbox).
- Dịch vụ chạy liên tục có HTTP API: ArchiveGuard là công cụ dòng lệnh theo lô (số liệu qua `--stats`).
- Tự gửi file lên dịch vụ bên ngoài: chỉ tra mã băm, và chỉ khi người dùng bật (`--virustotal`).

## Đã xong gần đây

| Bản | Nội dung |
|---|---|
| 0.17.1 | Vá lỗi bảo mật: file nén gắn sau dữ liệu khác (SFX, byte rác ở đầu), treo ở FIFO, kết quả ClamAV gộp ở process chính, hard timeout với process cháu `setsid`, trạng thái sandbox macOS |
| 0.17.0 | Macro VBA (giải nén mã nguồn), template Office từ xa, LNK, PowerShell mã hóa, cấu trúc ZIP, URLhaus, VirusTotal |
| 0.16.0 | `--update-db` có chữ ký, file cấu hình, `--fail-on`, `--allowlist`, `--stats`; lock file có hash, release ký Sigstore + SBOM |
| 0.15.0 | YARA signature-base (140 file, DRL 1.1), mã băm có ngày (bỏ mẫu > 12 tháng), script lấy mẫu đo recall |
| 0.14.0 | Dò chuỗi bằng YARA (~25× nhanh hơn), giải nén 7z một lượt |
| 0.13.0 | seccomp chặn mọi socket, clamdscan ở process chính, biến môi trường tối thiểu cho worker |
| 0.12.0 | Tách severity/confidence, luật ngữ cảnh, mã MITRE ATT&CK |

Chi tiết: [CHANGELOG.md](../CHANGELOG.md).
