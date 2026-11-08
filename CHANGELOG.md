# Lịch sử thay đổi

Định dạng theo [Keep a Changelog](https://keepachangelog.com/vi/1.1.0/). Phiên bản theo `MAJOR.MINOR.PATCH`;
trước 1.0, MINOR tăng khi có tính năng mới hoặc thay đổi hành vi.

Danh sách mã băm MalwareBazaar được cập nhật tự động hằng tuần và không được ghi ở đây.

## [Chưa phát hành]

### Bảo mật
- **Né phát hiện bằng byte rác ở đầu file nén:** ZIP có vài byte trước magic, ZIP/7z/RAR gắn sau một PE (SFX) hoặc
  sau dữ liệu nhị phân khác không được giải nén và có thể bị kết luận SẠCH, dù 7-Zip/unzip vẫn mở được. Giờ chúng
  được giải nén và quét như file nén thường (`extract.embedded_archive`); quét thư mục cũng nhận ra ZIP dạng này.
- **Quét thư mục bị treo vĩnh viễn** khi gặp FIFO hoặc file thiết bị: giờ chỉ mở file thường.
- **Kết quả clamdscan không còn đi qua worker:** process chính tự gộp phát hiện của ClamAV vào báo cáo sau khi worker
  trả về; worker bị khai thác không xóa được chúng. Yêu cầu gửi worker chỉ còn cờ `clamd_done`.
- **Hard timeout không còn bị vô hiệu hóa** khi một process cháu tự tách khỏi process group (`setsid`) mà giữ
  stdout: output của worker ghi ra file tạm thay vì pipe.
- ClamAV: output có tên file sai bảng mã không còn làm crash cả lần quét; đường dẫn truyền cho ClamAV là tuyệt đối.
- macOS: trạng thái sandbox không còn báo `filesystem_restricted: true` (sandbox-exec chỉ chặn ghi, vẫn đọc được mọi
  file) – `--require-sandbox` giờ từ chối quét trên macOS, giống Windows.

### Khác
- Phiên bản chỉ khai báo một chỗ (`pyproject.toml`); `__version__` đọc từ metadata của gói.

### Tài liệu & cộng đồng
- Bốn tab trên trang GitHub, mỗi tab một nhóm người đọc: README rút gọn thành trang giới thiệu; CONTRIBUTING chỉ cho
  người đóng góp (việc của người giữ repo chuyển sang `docs/MAINTAINING.md`); SECURITY.md chỉ còn chính sách (phần kỹ
  thuật chuyển sang `docs/SECURITY-MODEL.md`); `THIRD_PARTY_NOTICES.md` ghi giấy phép/điều khoản của luật
  signature-base, dữ liệu abuse.ch và file mẫu rarfile (LICENSE giữ nguyên văn MIT để GitHub nhận diện), và được
  đóng gói kèm wheel.
- README: "Khi nào KHÔNG nên dùng". Thêm docs/TROUBLESHOOTING.md, docs/INTEGRATION.md (GitHub Actions, GitLab CI,
  pre-commit, Docker), docs/ROADMAP.md.
- `.pre-commit-hooks.yaml`: dùng ArchiveGuard làm hook pre-commit (`id: archiveguard`).
- CONTRIBUTING: viết luật mới, đo báo nhầm trước khi merge, quy trình review luật. Manifest các bộ phần mềm sạch có
  thêm cột nguồn; `benchmark/tai_bo_sach.py` tải lại đúng từng byte (kiểm tra SHA-256);
  `benchmark/dung_mau_tong_hop.py` ghi bộ mẫu tổng hợp ra thư mục.
- SECURITY.md: phạm vi chi tiết (parser, sandbox, báo cáo, chuỗi cung ứng, bí mật), thời gian phản hồi, chính sách PGP.
- Mẫu issue "Báo nhầm" và "Bỏ sót" tách riêng, có trường cấu trúc (thay mẫu chung cũ) và nhãn tương ứng.

### Sửa
- Dòng trạng thái không còn ghi tên bộ luật signature-base khi chưa cài yara-python.

## [0.17.0] – 2026-11-03

### Thêm
- Office: giải nén mã nguồn VBA (MS-OVBA) trong `.doc/.xls` và `vbaProject.bin` của `.docm/.xlsm`;
  `DOC.MACRO_AUTOEXEC_EXEC` (macro tự chạy + gọi lệnh/tải file), luật hành vi chạy trên mã nguồn VBA;
  `DOC.REMOTE_RESOURCE` (template/đối tượng tải từ ngoài, T1221, gồm cả `ms-msdt:`); `DOC.XLM_MACRO`.
- `.lnk`: đọc cấu trúc MS-SHLLINK; `LNK.LOLBIN` (đích là cmd/powershell/mshta/rundll32… kèm tham số),
  `LNK.PADDED_ARGS`.
- `EXEC.PS_ENCODED`: giải mã PowerShell `-EncodedCommand` trong `.lnk`/script rồi chạy luật hành vi trên lệnh đã giải mã.
- Cấu trúc ZIP: `ARCHIVE.OVERLAP` (entry dùng chung dữ liệu), `ARCHIVE.HIDDEN_ENTRY` (local header không có trong
  danh mục); `NAME.CONTROL_CHARS`.
- `ENTROPY.ENCRYPTED_BLOB` (mức khả năng): dữ liệu không rõ định dạng có entropy ≥ 7,95.
- Nguồn mã băm thứ hai: URLhaus (cùng Auth-Key). `--virustotal` + `--vt-limit`: tra mã băm trên VirusTotal (tùy chọn).
- Phiên bản + nguồn + giấy phép của bộ luật YARA đi kèm hiện trong dòng trạng thái và JSON (`engines.yara`).
- 6 mẫu dương tính tổng hợp mới; 0 báo nhầm mới trên 260 gói phần mềm sạch (docs/BENCHMARK.md, vòng 5).

## [0.16.0] – 2026-11-03

### Vận hành
- `--update-db`: tải danh sách mã băm đã ký từ GitHub Release `hash-db`, xác minh chữ ký Sigstore (đúng workflow
  `update-hashes.yml` trên `main`) trước khi ghi; không cần Auth-Key. Cần `pip install "archive-guard[update]"`.
- Workflow `update-hashes` chạy hằng ngày: ký + đăng Release `hash-db` và tự kiểm tra bằng `--update-db`; thứ Hai
  commit vào main qua GitHub API (commit được GitHub ký).
- `--config FILE` (TOML) và biến môi trường `ARCHIVEGUARD_<TÊN>`; dòng lệnh > biến môi trường > file > mặc định.
  Không tự đọc file cấu hình trong thư mục hiện tại.
- `--fail-on suspicious,malicious,incomplete`: chọn kết luận nào làm lệnh thất bại; lỗi luôn là mã 3.
- `--allowlist FILE`: `sha256:` hoặc `path:` (đường dẫn trên đĩa); không bao giờ che mã độc đã biết; phát hiện bị bỏ
  qua vẫn ghi trong JSON (`allowlisted`, `suppressed`).
- `--stats FILE`: số liệu Prometheus (kết luận, số file, lỗi, thời gian, mã thoát) cho node_exporter/Pushgateway.
- Thêm dependency `tomli` (chỉ Python 3.10).

### Chuỗi cung ứng
- Lock file có hash (`requirements.txt`, `requirements-dev.txt`, `.github/requirements-tools.txt`, tạo bằng
  `uv pip compile`); CI, Docker và release đều cài bằng `pip install --require-hashes`. CI kiểm tra lock khớp
  `pyproject.toml`.
- `pip-audit` trên mọi dependency đã pin, mỗi lần push và mỗi ngày. Dependabot cho pip (2 thư mục), GitHub Actions
  và Docker.
- Mọi GitHub Action pin theo SHA commit; workflow mặc định chỉ có quyền đọc.
- Workflow `release`: build tái lập (wheel), SBOM CycloneDX, provenance SLSA + chữ ký Sigstore, PyPI Trusted
  Publishing với attestation PEP 740, GitHub Release kèm `SHA256SUMS`. Cách xác minh: SECURITY.md.
- Dockerfile: base image pin theo digest; **thêm `unrar`** (pin phiên bản + SHA-256 từ snapshot.debian.org) để image
  đọc được nội dung RAR; CI build `--no-cache` và quét thử RAR có mật khẩu trong container cứng hóa.
- SECURITY.md: bảng các thành phần đã pin, cách xác minh bản phát hành, lịch sử CVE của unrar, 7-Zip, ClamAV.

## [0.15.0] – 2026-11-01

### Thêm
- 140 file luật YARA `crime_*`/`mal_*` của signature-base (Detection Rule License 1.1) trong
  `archive_guard/data/rules/signature-base/`; 0 báo nhầm trên 260 gói phần mềm sạch. Luật kiểu THOR: mức độ suy
  từ `score`, in tên tác giả luật khi khớp (yêu cầu của DRL), có sẵn biến ngoài `filename`… (rỗng).
- Mọi file luật YARA được biên dịch chung để quét một lượt (lỗi thì biên dịch từng file, bỏ file lỗi).
- `benchmark/lay_mau.py`: lấy ≈ 200 mẫu MalwareBazaar mới theo họ, chia theo thời gian thành phần chỉnh luật và
  phần kiểm tra; từ chối chạy nếu không xác nhận đang ở máy ảo.

### Đổi
- Danh sách mã băm có thêm cột ngày `first_seen`; `update()` bỏ mã của mẫu cũ hơn 12 tháng. Dòng cũ chưa có ngày
  mà lượt cập nhật không thấy lại thì bị bỏ (trừ khi có truy vấn lỗi).

### Test và CI
- Test RAR với file thật (`tests/data/`: RAR5 thường và RAR5 có mật khẩu, từ bộ test của rarfile): đọc nội dung,
  thiếu/sai mật khẩu → CHƯA QUÉT ĐỦ, và unrar chạy được bên trong worker có sandbox. CI Ubuntu cài unrar; trên
  CI Linux test này thất bại thay vì bị bỏ qua nếu thiếu unrar.
- CI chạy thêm trên `ubuntu-24.04-arm` (bộ test + sandbox-report): ghi lại trạng thái sandbox trên arm64, nơi
  seccomp chưa hỗ trợ, và giữ cho trạng thái không bị báo quá mức thực tế.

## [0.14.0] – 2026-11-01

### Tăng tốc
- Dò chỉ dấu hành vi bằng **một luật YARA** (`ascii wide nocase`) khi có yara-python: ~270–330 MB/s thay vì ~8–12 MB/s (đo trên dữ liệu ngẫu nhiên và opengl32sw.dll 21 MB).
  Tên họ mã độc vẫn qua bước kiểm tra ranh giới token như cũ; thiếu yara-python hoặc YARA báo lỗi thì dùng vòng
  lặp cũ. yara-python vẫn là tùy chọn (`[yara]`) vì chưa có bản dựng sẵn cho mọi nền tảng (vd. Windows + Python 3.14).
- 7z giải nén **một lượt** trong luồng phụ, từng file chuyển qua hàng đợi; trước đây mỗi lô mở lại file và giải nén
  lại khối solid từ đầu. Lỗi ngân sách của luồng phụ được ném lại ở luồng chính.
- Benchmark trên 3 bộ phần mềm sạch + 22 mẫu tổng hợp (282 mẫu): kết luận và luật **giống hệt** bản trước; tổng thời
  gian quét giảm ~3 lần (p95 mỗi mẫu 11–14 s → 2,6–3,8 s).

### Đổi
- Cần `py7zr >= 1.1.3` (báo từng file giải nén xong qua `Py7zIO.close()`).

## [0.13.0] – 2026-11-01

### Bảo mật
- **seccomp chặn mọi `socket()`, kể cả Unix socket.** Trước đây worker bị khai thác vẫn kết nối được tới Unix socket
  dạng đường dẫn ngoài sandbox (clamd, D-Bus…) dù đã có network namespace và Landlock.
- `clamdscan` chuyển sang process chính và dùng `--fdpass`; worker chỉ còn gọi `clamscan`.
- Worker chỉ nhận biến môi trường tối thiểu (`PATH`, `LANG`/`LC_*`, `SYSTEMROOT`, `TMP*`, `PYTHON*`): khóa
  `ABUSECH_AUTH_KEY`, token… không còn lọt vào process xử lý dữ liệu không tin cậy.
- Trên Linux không có seccomp (máy không phải x86_64), trạng thái ghi `network_blocked: false`; `--require-sandbox`
  từ chối quét thay vì báo đã chặn mạng.
- SECURITY.md: cô lập bảo vệ máy, không bảo đảm kết luận đúng nếu worker đã bị khai thác.
- `python -m archive_guard.sandbox` thử thêm `ket_noi_unix`.

## [0.12.0] – 2026-10-31

### Đổi
- **Tách severity và confidence.** Mỗi phát hiện có thêm `confidence` (`low` = khả năng, `medium`, `high`) và
  `attack` (mã MITRE ATT&CK). 9 luật là *khả năng* (vd. `KEYLOG.API`, `INJECT.PROCESS`, `DOWNLOAD.API`): một mình
  chúng không còn gắn cờ, trừ khi một file có khả năng ở ≥ 3 nhóm hành vi.
- **NGUY HIỂM cần ≥ 2 chỉ dấu độc lập** (trừ mã băm, ClamAV, YARA critical); một luật HIGH đơn lẻ là ĐÁNG NGỜ.
- `BACKDOOR.REVERSE_SHELL` cần cả phần mở shell lẫn kết nối mạng.
- `BACKDOOR.KNOWN_RAT` so khớp theo token: tên họ không được nối tiếp bằng chữ thường (`dcrates` ≠ `DcRat`).
- Báo nhầm trên bộ kiểm tra chưa dùng để chỉnh luật: phần mềm thông dụng 5,9% → 2,0%; 22/22 mẫu tổng hợp vẫn bị bắt.
  Chi tiết và đánh đổi: docs/BENCHMARK.md, vòng 3.

### Thêm
- Luật ngữ cảnh `KEYLOG.EXFIL`, `STEAL.EXFIL`, `INJECT.LOADER` (khả năng + bằng chứng bổ trợ trong cùng file).
- YARA: `meta` nhận thêm `confidence` và `attack`.
- Văn bản báo cáo hiện mã ATT&CK và nhãn `khả năng`; JSON thêm hai trường (vẫn `schema_version` 1).
- `tests/positives.py`: 22 mẫu dương tính tổng hợp dùng làm test hồi quy.

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
