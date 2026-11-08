# Xử lý sự cố

Tìm theo **thông báo** in ra (gõ Ctrl+F với một đoạn của nó). Mã thoát: 0 sạch · 1 đáng ngờ · 2 nguy hiểm ·
3 lỗi · 4 chưa quét đủ. Mọi phần chưa quét được đều hiện ở dòng `! Chưa kiểm tra được: …` và trong JSON
(`reports[].incomplete`).

## Mã thoát 4 – CHƯA QUÉT ĐỦ

| Thông báo | Nguyên nhân | Cách xử lý |
|---|---|---|
| `cần cài unrar hoặc 7-Zip để đọc nội dung RAR` | Máy không có công cụ đọc RAR | Ubuntu/Debian: `sudo apt install unrar` (gói `non-free`). Windows: cài 7-Zip và thêm `C:\Program Files\7-Zip` vào `PATH`. macOS: `brew install rar`. Docker image đã có sẵn `unrar` |
| `lỗi đọc: Failed the read enough data …` khi quét RAR | Có công cụ nhưng không giải nén được RAR5: `bsdtar` của macOS hoặc `p7zip` của Homebrew (không có codec RAR) | Cài `unrar` như trên; rarfile tự ưu tiên `unrar` |
| `được đặt mật khẩu, không đọc được nội dung` | File con có mật khẩu | `-p MẬT_KHẨU` (lặp lại được). Không biết mật khẩu thì kết quả đúng là CHƯA QUÉT ĐỦ – đây là thủ thuật né antivirus phổ biến |
| `RAR bị mã hóa cả danh sách file` / `7z bị mã hóa cả danh sách file` | Mã hóa cả tên file | Như trên; RAR mã hóa cả tên hiện chưa thử được mật khẩu |
| `… file nén lớn hơn N MB (--max-archive-size)` | File nén đầu vào vượt giới hạn | Tăng `--max-archive-size` nếu máy đủ tài nguyên |
| `… lớn hơn giới hạn, bỏ qua nội dung` | Một file con lớn hơn `--max-size` (mặc định 256 MB) | Tăng `--max-size`; cân nhắc RAM vì file con được đọc vào bộ nhớ |
| `… dừng – Tổng dung lượng giải nén vượt N MB – nghi zip bomb` / `… dừng – Hơn N entry bên trong – dừng quét` / `ARCHIVE.TIMEOUT` | Chạm ngân sách chung (`--max-total`, 20.000 entry, `--timeout`) – có thể là archive bomb | Nếu chắc chắn file hợp lệ: tăng `--max-total`/`--timeout`. Nếu kèm `ARCHIVE.BOMB_*`/`ARCHIVE.OVERLAP`: **đừng giải nén file đó** |
| `… lồng quá sâu` | Hơn `--max-depth` tầng file nén lồng nhau | Tăng `--max-depth` (mặc định 5) |
| `định dạng CAB/ISO/WIM/Zstandard/… chưa được giải nén, chỉ quét dạng thô` | Định dạng chưa hỗ trợ | Giải nén bằng công cụ khác trong máy ảo rồi quét các file bên trong |
| `ClamAV không chạy được hoặc hết thời gian quét (thiếu cơ sở dữ liệu? …)` | Có `clamscan` nhưng chưa có cơ sở dữ liệu chữ ký, hoặc hết giờ, hoặc thiếu RAM | `sudo freshclam`; tăng `--timeout`; với `--worker-memory` dưới ~1,5 GB thì ClamAV không chạy được; hoặc `--no-clamav` |
| `worker bị dừng sau N giây (hard timeout)` | Worker treo hoặc file quá nặng | Tăng `--worker-timeout`/`--timeout`; nếu lặp lại với một file cụ thể, hãy báo lỗi (có thể là lỗ hổng parser – xem SECURITY.md) |
| `YARA lỗi: …` / `heuristic lỗi: …` | Engine lỗi với file đó | Báo lỗi kèm SHA-256 của file |

## Mã thoát 3 – lỗi

| Thông báo | Nguyên nhân | Cách xử lý |
|---|---|---|
| `Lỗi: --require-sandbox nhưng worker thiếu: giới hạn truy cập file, chặn mạng (…)` | Máy không có đủ sandbox (xem bảng dưới) | Chạy trong Docker/WSL trên Linux x86_64, hoặc bỏ `--require-sandbox` nếu chấp nhận rủi ro |
| `worker lỗi (mã thoát N): …` | Worker crash. Mặc định chỉ hiện dòng cuối stderr của worker | Chạy lại với `--debug` để xem cả traceback; thử `--no-sandbox` để biết có phải do sandbox không; báo lỗi kèm output `--debug`, hệ điều hành, kernel (`uname -r`) |
| `worker trả kết quả không hợp lệ: …` | Báo cáo của worker cụt, sai cấu trúc hoặc tự mâu thuẫn (phần sau dấu `:` cho biết lý do) – có thể worker đã bị khai thác | Giữ lại file, báo riêng qua SECURITY.md |
| `không tạo được Job Object để giới hạn RAM (WinError …)` | Windows không cho gắn worker vào Job Object (vd. đã nằm trong một job khác) | Bỏ `--worker-memory` hoặc chạy ngoài môi trường đó |
| `Lỗi: không đọc được …` | Không có quyền đọc file/thư mục | Kiểm tra quyền; chạy bằng user có quyền đọc |
| `Lỗi cập nhật: Auth-Key bị từ chối (HTTP 401)` / `thiếu Auth-Key` | `--update-hashes` cần Auth-Key của abuse.ch | Đăng ký miễn phí tại auth.abuse.ch, đặt `ABUSECH_AUTH_KEY`. Hoặc dùng `--update-db` (không cần Auth-Key) |
| `Lỗi cập nhật: cần thư viện sigstore để xác minh chữ ký` | `--update-db` thiếu thư viện | `pip install "archive-guard[update]"` |
| `Lỗi cập nhật: chữ ký KHÔNG hợp lệ, không dùng file này` | File tải về không do workflow của repo ký, hoặc tải dở | Thử lại sau vài phút (Release đang được cập nhật). Nếu vẫn lỗi, **không** dùng file đó và báo riêng qua SECURITY.md |

`Lỗi khi quét …: <Kiểu lỗi>: …` (với `--no-isolate`) là lỗi ngoài dự kiến của chính ArchiveGuard: chạy lại với
`--debug` và đính kèm traceback khi báo lỗi.

Lỗi tham số (sai tên tùy chọn trong file cấu hình, allowlist sai định dạng, `--fail-on` sai giá trị…) trả **mã 2**
của argparse, kèm dòng cho biết file và dòng gây lỗi.

## Sandbox không bật đủ

Chạy `python -m archive_guard.sandbox` để xem lớp nào hoạt động và thử các thao tác bị cấm ngay trên máy bạn.

| Trạng thái | Nguyên nhân | Hệ quả |
|---|---|---|
| `landlock: không hỗ trợ (ENOSYS)` | Kernel < 5.13 hoặc không bật Landlock (`CONFIG_SECURITY_LANDLOCK`, `lsm=…,landlock`) | Worker đọc/ghi được file ngoài thư mục tạm. Nâng kernel, hoặc dùng Docker trên máy có Landlock |
| `landlock: bật (ABI 1–3)` (không có "chặn TCP") | Kernel 5.13–6.6: Landlock chưa chặn được TCP | Mạng vẫn bị chặn nếu seccomp bật |
| `network_namespace: không được (Operation not permitted)` | Không có user namespace không đặc quyền (Docker, Ubuntu có AppArmor hạn chế userns, RHEL…) | Không sao nếu seccomp bật: seccomp chặn mọi `socket()` |
| `seccomp: bỏ qua: chỉ hỗ trợ x86_64 (máy này: aarch64)` | Máy ARM | `network_blocked: false`: Unix socket còn mở; `--require-sandbox` sẽ từ chối quét. Dùng máy x86_64 cho dữ liệu không tin cậy |
| `chưa có sandbox file/mạng trên hệ điều hành này` | Windows | Chỉ có cô lập process (RAM, CPU, kill cả cây). Dùng Docker Desktop hoặc WSL2 |
| macOS: `doc_file_ca_nhan: true` | sandbox-exec chỉ chặn ghi và mạng | Worker vẫn đọc được file của bạn |

## Kết quả không như mong đợi

- **File của tôi sạch nhưng bị ĐÁNG NGỜ:** xem mã luật và dòng `khớp:` trong báo cáo. Nếu là công cụ bạn tin dùng,
  thêm vào `--allowlist` (SHA-256), và hãy mở issue **"Báo nhầm"** để luật được sửa cho mọi người.
- **Mã độc bị coi là SẠCH:** mở issue **"Bỏ sót"** kèm SHA-256 (không gửi mẫu). Heuristic không thay được
  antivirus – xem "Khi nào không nên dùng" trong README.
- **Quét chính repo ArchiveGuard ra NGUY HIỂM:** bình thường – `rules.py`, luật YARA và test chứa đúng các chuỗi cần dò.
- **Python cảnh báo `Overlapped entries … (possible zip bomb)`:** cảnh báo của thư viện `zipfile` với ZIP có entry
  chồng nhau; ArchiveGuard đã báo `ARCHIVE.OVERLAP`.
- **Chậm:** cài `yara-python` (`pip install -e ".[yara]"`): dò chuỗi nhanh hơn ~25 lần. ClamAV thường là phần chậm
  nhất; `clamdscan` (daemon) nhanh hơn nhiều so với `clamscan`.
