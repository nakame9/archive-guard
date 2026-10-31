# Lịch sử thay đổi

Định dạng theo [Keep a Changelog](https://keepachangelog.com/vi/1.1.0/). Phiên bản theo `MAJOR.MINOR.PATCH`;
trước 1.0, MINOR tăng khi có tính năng mới hoặc thay đổi hành vi.

Danh sách mã băm MalwareBazaar được cập nhật tự động hằng tuần và không được ghi ở đây.

## [Chưa phát hành]

## [0.11.0] – 2026-10-31

### Đổi
- **Mặc định cô lập:** parser không còn chạy trong process chính; mỗi file nén được quét trong một worker.
  `--no-isolate` để quay lại cách cũ (không khuyến khích với dữ liệu không tin cậy); `--isolate` giữ để tương thích.
- Mã thoát của script cũ không đổi; mỗi file nén tốn thêm ~0,1 giây.

### Thêm
- Sandbox hệ điều hành trong worker: Linux – no_new_privs, network namespace, Landlock (chỉ đọc file đầu vào +
  thư viện, chỉ ghi thư mục tạm, chặn TCP), seccomp x86_64 (chặn ptrace, mount, bpf, socket mạng…), RLIMIT_CORE=0;
  macOS – sandbox-exec (chặn mạng, chặn ghi ngoài thư mục tạm).
- Giới hạn CPU cho worker (RLIMIT_CPU; Windows: Job Object).
- `--require-sandbox`, `--no-sandbox`; trường `sandbox` trong báo cáo JSON; `python -m archive_guard.sandbox`.
- Process chính kiểm tra cấu trúc kết quả của worker và lọc ký tự điều khiển terminal trước khi in.
- Dockerfile chạy bằng user thường; CI build image và quét thử trong container cứng hóa.

### Tổ chức lại repo
- Tổ chức lại repo: test tách theo mảng (`tests/test_*.py` + `tests/helpers.py`), README rút gọn, tài liệu chi tiết
  chuyển vào `docs/` (USAGE, ARCHITECTURE, RULES), thêm CONTRIBUTING, SECURITY, CHANGELOG.
- CI: thêm job lint (ruff), cập nhật action lên Node 24, mẫu issue/PR, dependabot.
- Ký tự đảo chiều Unicode trong mã nguồn được viết dưới dạng escape `\u202e` (giá trị không đổi).

## [0.10.0] – 2026-10-31

### Thêm
- Giải nén **streaming**: ngân sách byte và thời gian được tính sau mỗi khúc 1 MB, dừng ngay giữa chừng file con.
- Mọi entry, kể cả thư mục, được đếm ngay khi duyệt; ZIP đọc số entry và kích thước danh mục từ EOCD/ZIP64 để
  chặn **trước khi** nạp metadata.
- `--max-archive-size` (mặc định 4096 MB) cho file nén đầu vào.

## [0.9.0] – 2026-10-31

### Thêm
- `--isolate`: mỗi file nén quét trong một process con; `--worker-timeout` (hard timeout, kill cả cây process),
  `--worker-memory` (Linux: RLIMIT_AS, Windows: Job Object). Mật khẩu truyền qua stdin.

## [0.8.0] – 2026-10-31

### Sửa
- `BACKDOOR.KNOWN_RAT`: tên họ mã độc phải đứng đầu một từ (báo nhầm ở các file nhị phân Rust).
- `RANSOM.NOTE`: cần cả lời đòi tiền chuộc lẫn cách trả tiền (báo nhầm ở esbuild).
- Báo nhầm ở phần mềm thông dụng trên bộ kiểm tra: 11,3% → 4,2%.

## [0.7.0] – 2026-10-30

### Thêm
- `schema_version` và `rules_version` (tự sinh từ nội dung luật) trong báo cáo JSON.

### Sửa
- ClamAV và YARA không còn chạy quá `--timeout` (ClamAV trước đó cố định 900 giây).

## [0.6.0] – 2026-10-30

### Thêm
- Kết luận `CHƯA QUÉT ĐỦ` (mã thoát 4): file có mật khẩu, file hỏng, định dạng chưa hỗ trợ (CAB, ISO, WIM…),
  engine lỗi không còn bị báo SẠCH.

## [0.5.0] – 2026-10-30

### Thêm
- `python -m archive_guard.benchmark`: precision, recall, tỷ lệ báo nhầm kèm khoảng tin cậy 95%.
- Số liệu báo nhầm đo trên 109 gói phần mềm thật.

## [0.4.0] – 2026-10-29

### Thêm
- Ngân sách tài nguyên dùng chung cho mọi tầng lồng nhau, đếm byte thực tế; 7z giải nén theo lô; `--max-total`, `--timeout`.

## [0.3.1] – 2026-10-29

### Sửa
- Dò chuỗi hành vi và entropy trên **trọn** file (trước: 32 MB đầu + 4 MB cuối); nâng giới hạn của `clamscan`.

## [0.3.0] – 2026-10-27

### Thêm
- Phát hiện packer: tên section, dấu `UPX!`, entropy vùng mã.

## [0.2.0] – 2026-10-27

### Thêm
- `--update-hashes`: tải mã băm theo họ từ MalwareBazaar; workflow cập nhật hằng tuần.

## [0.1.0] – 2026-10-27

- Phiên bản đầu tiên: quét ZIP/RAR/7z/TAR/GZ trong bộ nhớ, luật tên file, chỉ dấu hành vi, mã băm, YARA, ClamAV.
