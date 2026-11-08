# ArchiveGuard 🛡️

[![tests](https://github.com/nakame9/archive-guard/actions/workflows/tests.yml/badge.svg)](https://github.com/nakame9/archive-guard/actions/workflows/tests.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

Công cụ dòng lệnh quét **file nén** (ZIP, RAR, 7z, TAR, GZ, BZ2, XZ, Office Open XML…) tìm dấu hiệu **trojan,
keylogger, worm, ransomware, stealer, backdoor/RAT, downloader** – *trước khi* bạn giải nén hay mở bất cứ thứ gì.

> ⚠️ ArchiveGuard **không cam kết file an toàn**. Nó cho biết đã kiểm tra những gì, phát hiện những gì, và quá trình
> kiểm tra có hoàn tất, đáng tin cậy hay không. Công cụ bổ sung cho antivirus, không thay thế. Xem
> [Khi nào không nên dùng](#khi-nào-không-nên-dùng) và [mô hình đe dọa](docs/THREAT_MODEL.md).

## Tính năng chính

- **Không giải nén ra đĩa**, đi vào file nén lồng nhau với **ngân sách tài nguyên chung** chống archive bomb.
- **Parser chạy trong worker có sandbox** (Linux: Landlock + seccomp + chặn mạng; macOS: sandbox-exec chặn ghi và
  mạng), hard timeout, giới hạn CPU/RAM. Process chính không tin kết quả của worker: tự gộp phát hiện của ClamAV và
  từ chối báo cáo sai cấu trúc. Có image Docker cứng hóa.
- **Nhiều lớp phát hiện:** tên file giả mạo, packer, chuỗi hành vi (gắn mã MITRE ATT&CK), macro Office, shortcut
  `.lnk`, PowerShell mã hóa, cấu trúc ZIP bất thường, mã băm MalwareBazaar + URLhaus, YARA (kèm luật signature-base),
  ClamAV và VirusTotal (tùy chọn).
- **Không bao giờ báo SẠCH khi chưa quét hết:** file có mật khẩu, hỏng, quá lớn, định dạng chưa hỗ trợ, file nén giấu
  sau dữ liệu khác → được giải nén hoặc `CHƯA QUÉT ĐỦ`, kèm mã lý do trong JSON. Bất biến này được kiểm thử bằng cách
  tiêm lỗi vào từng parser và engine.
- **Vận hành:** file cấu hình, `--fail-on` cho pipeline, `--allowlist`, số liệu Prometheus, cập nhật mã băm có chữ ký.

## Cài đặt

Cần Python 3.10+.

```bash
git clone https://github.com/nakame9/archive-guard.git && cd archive-guard
pip install --require-hashes -r requirements.txt && pip install --no-deps -e .   # đúng phiên bản đã kiểm tra
```

Nên có thêm `unrar` (đọc nội dung RAR) và ClamAV (tùy chọn) – xem [Cài thêm](docs/USAGE.md#cài-thêm).
Docker: [docs/USAGE.md#docker](docs/USAGE.md#docker).

## Dùng nhanh

```bash
archiveguard file.zip                       # quét một file
archiveguard Downloads/                     # quét mọi file nén trong thư mục
archiveguard tailieu.rar -p 123456          # thử mật khẩu
archiveguard file.zip --json baocao.json    # báo cáo JSON
archiveguard Downloads/ --require-sandbox   # từ chối quét nếu máy thiếu sandbox
```

```text
== hoa-don-thang-10.zip ==
  [NGUY HIỂM 100] hoa-don-thang-10.zip > HoaDon_T10.pdf.exe
      HIGH     Trojan / ngụy trang: Đuôi kép giả mạo: trông như .pdf nhưng thực ra là .exe [T1036.007]
      HIGH     Keylogger (ghi phím): Bắt phím VÀ gửi dữ liệu ra ngoài – chuỗi hành vi của keylogger [T1056.001]
               khớp: api.telegram.org/bot, getasynckeystate
      MEDIUM   Stealer (đánh cắp dữ liệu): Gửi dữ liệu ra ngoài qua Telegram bot / Discord webhook / SMTP [T1567] · khả năng
  [ĐÁNG NGỜ 30] hoa-don-thang-10.zip > autorun.inf
      MEDIUM   Worm (tự lây lan): autorun.inf – cơ chế tự chạy mà worm USB hay dùng [T1091]
  KẾT LUẬN: NGUY HIỂM – dấu hiệu: Keylogger (ghi phím), Stealer (đánh cắp dữ liệu), Trojan / ngụy trang, Worm (tự lây lan)
```

`[T…]` là mã MITRE ATT&CK; `khả năng` = API mà phần mềm hợp pháp cũng dùng, một mình không đủ gắn cờ.

| Kết luận | Mã thoát | Ý nghĩa |
|---|---|---|
| SẠCH | `0` | Đã kiểm tra **toàn bộ** nội dung, không thấy dấu hiệu nguy hiểm |
| ĐÁNG NGỜ | `1` | Có dấu hiệu cần xem lại |
| NGUY HIỂM | `2` | Dấu hiệu mạnh hoặc trùng mã độc đã biết |
| *(lỗi)* | `3` | Không đọc được file, worker crash… |
| CHƯA QUÉT ĐỦ | `4` | Có phần chưa kiểm tra được – **không được coi là sạch** |

## Độ chính xác đã đo

Trên 70 gói phần mềm sạch **chưa từng dùng để chỉnh luật**: phần mềm thông dụng bị gắn ĐÁNG NGỜ **2,0%**, công cụ
hai mặt (debugger, kiểm thử xâm nhập, hook bàn phím) **10,5%**, NGUY HIỂM **0%**. **Recall trên mã độc thật chưa
được đo.** Phương pháp, số liệu từng vòng và cách tự đo: [docs/BENCHMARK.md](docs/BENCHMARK.md).

## Khi nào không nên dùng

| Tình huống | Vì sao | Nên làm gì |
|---|---|---|
| Thay cho antivirus/EDR | Không giám sát thời gian thực, không chạy thử file, không gỡ mã độc | Dùng như lớp **kiểm tra trước khi giải nén**, bên cạnh AV |
| Mở file nhắm thẳng vào bạn chỉ vì kết luận SẠCH | Recall chưa đo; mã độc bị pack mạnh hoặc tải payload lúc chạy để lộ rất ít | Mở trong máy ảo, kết hợp công cụ khác |
| Máy cách ly mạng không cập nhật được | Danh sách mã băm cũ dần; heuristic và YARA vẫn chạy | Chép file mã băm đã ký từ Release `hash-db`, xác minh ở máy có mạng, dùng `--hashes` |
| File rất lớn, định dạng chưa hỗ trợ (ISO, CAB, WIM, Zstandard…) | Kết quả là CHƯA QUÉT ĐỦ | Tăng giới hạn, hoặc giải nén trong máy ảo rồi quét phần bên trong |
| Dữ liệu không tin cậy trên Windows/ARM không có Docker/WSL | Windows chưa có sandbox file/mạng; ARM chưa có seccomp | Docker/WSL2 trên Linux x86_64 + `--require-sandbox` |
| Tài liệu nhạy cảm kèm `--virustotal` | Mã băm gửi đi cho biết file đó tồn tại | Đừng bật `--virustotal` cho dữ liệu nội bộ |

## Tài liệu

| Bạn muốn | Đọc |
|---|---|
| Mọi tùy chọn, JSON, sandbox, Docker, cấu hình, `--fail-on`, allowlist, số liệu | [docs/USAGE.md](docs/USAGE.md) |
| Đưa vào GitHub Actions, GitLab CI, pre-commit | [docs/INTEGRATION.md](docs/INTEGRATION.md) |
| Gặp lỗi, mã thoát 4, sandbox không bật | [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) |
| Cách chấm điểm, các lớp phát hiện, thêm luật | [docs/RULES.md](docs/RULES.md) |
| Mô hình đe dọa: kẻ tấn công kiểm soát gì, sandbox chặn được gì | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) |
| Chuỗi cung ứng, xác minh bản phát hành | [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) |
| Hiểu code: module, luồng quét, muốn sửa X thì sửa ở đâu | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Định hướng sắp tới · lịch sử thay đổi | [docs/ROADMAP.md](docs/ROADMAP.md) · [CHANGELOG.md](CHANGELOG.md) |

## Đóng góp, báo lỗi, bảo mật

- **Báo nhầm / bỏ sót** (dữ liệu quý nhất để cải thiện luật): [mở issue](https://github.com/nakame9/archive-guard/issues/new/choose).
- **Đóng góp code hoặc luật:** [CONTRIBUTING.md](CONTRIBUTING.md).
- **Lỗ hổng bảo mật:** báo riêng theo [SECURITY.md](SECURITY.md), đừng mở issue công khai.

## Giấy phép

Mã nguồn: [MIT](LICENSE). Luật YARA, dữ liệu mã băm và file mẫu đi kèm có giấy phép/điều khoản riêng:
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Chỉ dùng cho mục đích phòng thủ và học tập.
