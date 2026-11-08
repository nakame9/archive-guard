# Mô hình đe dọa (Threat Model)

ArchiveGuard không cam kết file an toàn. Nó cho biết đã kiểm tra những gì, phát hiện những gì, và quá trình kiểm tra
có hoàn tất, đáng tin cậy hay không. Tài liệu này trả lời: kẻ tấn công kiểm soát được gì, ArchiveGuard chặn được gì,
và **không** chặn được gì. Áp dụng cho nhánh `main` sau bản 0.17.1. Chuỗi cung ứng và xác minh bản phát hành:
[SECURITY-MODEL.md](SECURITY-MODEL.md). Cách báo lỗ hổng: [SECURITY.md](../SECURITY.md).

**Bất biến cốt lõi** – mọi thay đổi code phải giữ: *nếu một bước bắt buộc không hoàn tất, kết luận không bao giờ là
SẠCH.* Bước bắt buộc = đọc file, giải nén từng tầng, kiểm tra cấu trúc ZIP, heuristic, YARA, ClamAV (trừ khi
`--no-clamav`), và worker trả báo cáo hợp lệ. Kiểm chứng tự động: `tests/test_failure_paths.py` (tiêm lỗi vào từng
parser và engine), `tests/test_isolate.py` (worker crash/treo/bị kill), `tests/test_sandbox.py`.

## Các bên và ranh giới tin cậy

| Thành phần | Tin cậy? | Ghi chú |
|---|---|---|
| Người chạy lệnh: tham số dòng lệnh, `--config`, biến `ARCHIVEGUARD_*`, allowlist, luật YARA, file mã băm thêm | Tin | Cấu hình **không** tự nạp từ thư mục hiện tại (có thể chính là thư mục chứa file cần quét) |
| Danh sách mã băm qua `--update-db` | Tin sau khi xác minh | Chỉ chấp nhận chữ ký Sigstore của workflow `update-hashes.yml` trên `main` |
| Process chính | Tin | Không phân tích nội dung file nén. Khi quét thư mục chỉ đọc 512 byte đầu và bản ghi cuối ZIP của từng file để chọn file nén; gọi `clamdscan --fdpass`; kiểm tra và đọc báo cáo của worker |
| Worker (`--_worker`) và process con của nó (unrar, clamscan) | **Không tin** | Phân tích toàn bộ dữ liệu không tin cậy; coi như có thể đã bị khai thác |
| File cần quét, mọi thứ bên trong nó | **Không tin** | Do kẻ tấn công tạo |
| Dịch vụ ngoài (VirusTotal, abuse.ch) | Tin một phần | Chỉ dùng để *thêm* phát hiện, không bao giờ để xóa phát hiện |

## 1. Kẻ tấn công kiểm soát được những đầu vào nào?

Toàn bộ **nội dung** file cần quét: định dạng, magic, cấu trúc, mọi metadata khai báo (kích thước, số entry, offset,
CRC, cờ mã hóa, phương thức nén), tên file bên trong (ký tự điều khiển terminal, ký tự đảo chiều Unicode, `../`,
byte null, tên trùng), symlink/hardlink trong TAR, dữ liệu gắn trước/sau file nén (SFX, polyglot).

Khi quét **thư mục** dùng chung (vd. thư mục upload): tên file trên đĩa, FIFO, file thiết bị, symlink. Và **thời
điểm**: file có thể bị thay giữa lúc quét và lúc bạn dùng (TOCTOU) – ArchiveGuard không chặn được, xem
[INTEGRATION.md](INTEGRATION.md).

**Không** kiểm soát: tham số dòng lệnh, cấu hình, allowlist, luật YARA, biến môi trường của process chính, mật khẩu
truyền bằng `-p`.

Cách xử lý: tên file in ra terminal được lọc ký tự điều khiển (`cli._safe`); quét thư mục chỉ mở file thường
(không treo ở FIFO); không bao giờ giải nén ra đĩa (unrar chạy `unrar p`, in ra stdout) nên path traversal không ghi
được gì; allowlist `path:` so với đường dẫn trên đĩa, không so với tên do file nén tự khai.

## 2. Có thể tạo archive lồng nhau với cấu trúc tùy ý không?

Có, và ArchiveGuard giả định là có. Chặn bằng **ngân sách chung cho mọi tầng** của một lần quét, kiểm tra **ngay
trong lúc** giải nén (sau mỗi khúc 1 MB, mỗi entry):

| Giới hạn | Mặc định | Vượt thì |
|---|---|---|
| Số tầng lồng nhau `--max-depth` | 5 | `ARCHIVE.TOO_DEEP` + `TOO_DEEP` |
| Số entry (kể cả thư mục) | 20.000 | `ARCHIVE.TOO_MANY_FILES` + `BUDGET_FILES`; danh mục ZIP khai báo quá lớn bị từ chối **trước** khi nạp |
| Tổng dung lượng giải nén `--max-total` | 4096 MB | `ARCHIVE.BOMB_TOTAL` + `BUDGET_BYTES` |
| Thời gian `--timeout` | 300 s | `ARCHIVE.TIMEOUT` + `BUDGET_TIME` |
| Mỗi file con `--max-size` | 256 MB | không đọc nội dung + `MEMBER_TOO_LARGE`; kích thước khai báo vẫn bị trừ vào ngân sách |
| Tỷ lệ nén của một file con ≥ 50 MB (cố định) | 100:1 | `ARCHIVE.BOMB_RATIO` + `MEMBER_BOMB` |

Không tin kích thước khai báo: luôn đọc tối đa `giới hạn + 1` byte. ZIP có vùng dữ liệu chồng nhau
(`ARCHIVE.OVERLAP`) hoặc entry có local header nhưng bị giấu khỏi danh mục (`ARCHIVE.HIDDEN_ENTRY`) được báo riêng.
File nén nằm sau dữ liệu khác (ZIP có byte rác ở đầu, ZIP/7z/RAR gắn sau PE) cũng được giải nén (0.17.1).

Giới hạn còn lại: py7zr và rarfile nạp **toàn bộ** danh mục 7z/RAR khi mở – danh mục cực lớn tốn RAM trước khi ngân
sách kịp chặn; dùng `--worker-memory` (Linux, Windows).

## 3. Parser được chạy với quyền gì?

Mặc định mọi parser chạy trong **worker**: một process con riêng cho mỗi file nén, **cùng user** với process chính
(không hạ quyền user), áp sandbox của hệ điều hành **trước khi đọc byte đầu tiên** của dữ liệu không tin cậy. Process
con của worker (unrar, clamscan) thừa hưởng mọi hạn chế.

Luôn có trên mọi hệ điều hành: thư mục làm việc là thư mục tạm rỗng (file `.py` lạ ở thư mục người dùng không che được
thư viện), biến môi trường tối thiểu (`PATH`, `LANG`/`LC_*`, `SYSTEMROOT`, `TMP*`, `PYTHON*` – không có khóa API,
token, `HOME`), mật khẩu qua stdin, hard timeout kill cả cây process, giới hạn CPU.

| Lớp | Linux | macOS | Windows |
|---|---|---|---|
| no_new_privs, không core dump | ✅ | – | – |
| Giới hạn file (Landlock) | ✅ | chỉ chặn ghi | ❌ |
| Chặn mạng | ✅ x86_64 (seccomp); arm64 một phần | ✅ sandbox-exec | ❌ |
| Chặn syscall nguy hiểm (ptrace, mount, bpf, io_uring…) | ✅ x86_64 | ❌ | ❌ |
| Giới hạn RAM `--worker-memory` | ✅ | ❌ | ✅ Job Object |

Windows: dự án đã quyết định **không** tự làm sandbox AppContainer; để có sandbox file và mạng, chạy ArchiveGuard
trong Docker Desktop hoặc WSL2 ([ROADMAP.md](ROADMAP.md#quyết-định-đã-chốt)).

`--no-isolate` chạy mọi parser **ngay trong process chính, không sandbox**: chỉ dùng với dữ liệu tin cậy.
`--require-sandbox` từ chối quét (mã 3) khi worker không giới hạn được truy cập file **và** chặn được mạng – hiện
chỉ đạt trên Linux x86_64 có Landlock.

## 4. Worker có thể đọc file bên ngoài không?

| Hệ điều hành | Đọc được | Ghi được |
|---|---|---|
| Linux (Landlock) | file đầu vào; thư viện Python (`sys.prefix`, các mục trong `sys.path`, kể cả site-packages của user); `/usr`, `/lib*`, `/bin`, `/sbin`, `/etc`, `/opt`, `/proc`, `/dev`, `/var/lib/clamav` | chỉ thư mục tạm riêng và `/dev/null` |
| macOS (sandbox-exec) | **mọi file** user đọc được, kể cả `~/.ssh` | chỉ thư mục tạm riêng |
| Windows | **mọi file** user đọc được | **mọi file** user ghi được |
| Linux kernel không có Landlock | **mọi file** | **mọi file** |

Trạng thái thật luôn ghi trong báo cáo (`sandbox.filesystem_restricted`); `python -m archive_guard.sandbox` thử đọc
một file cá nhân từ trong sandbox để kiểm chứng trên máy bạn.

## 5. Worker có thể kết nối Internet không?

| Hệ điều hành | Kết quả |
|---|---|
| Linux x86_64 | **Không**: seccomp chặn mọi `socket()` (kể cả Unix socket dạng đường dẫn như clamd), thêm network namespace rỗng và Landlock chặn TCP (ABI ≥ 4) |
| Linux arm64 | Không có card mạng (network namespace) nhưng **vẫn kết nối được Unix socket** → báo `network_blocked: false` |
| macOS | **Không** (sandbox-exec `deny network*`) |
| Windows | **Có** |

Vì vậy clamdscan (cần socket tới clamd) chạy ở process chính và chỉ chuyển file descriptor (`--fdpass`).

## 6. Nếu parser bị RCE thì kẻ tấn công làm được gì?

Giả định: lỗi hỏng bộ nhớ trong unrar, zlib, py7zr, yara-python… cho kẻ tấn công chạy mã trong worker.

**Làm được:**

- **Nói dối về kết luận**, trong giới hạn: process chính kiểm tra cấu trúc và tính nhất quán của báo cáo
  (`isolate.check_report`: đúng một báo cáo, có danh sách file, còn phần chưa quét thì không được SẠCH), nhưng một
  báo cáo SẠCH hợp lệ do worker bịa ra thì không phân biệt được với báo cáo thật.
- Bỏ phát hiện của **clamscan** khi máy không có clamd (clamscan chạy trong worker).
- Khai mã băm giả cho các file con, nên `--virustotal` tra sai file (mã băm do worker báo).
- Đốt CPU tới hard timeout; tạo process cháu tự tách khỏi nhóm (`setsid`) sống tiếp tới khi tự thoát, vẫn trong
  sandbox.
- Đọc file theo bảng ở câu 4; trên **Windows và macOS** đọc được file cá nhân; trên **Windows** gửi được ra mạng.

**Không làm được** (ở nơi sandbox báo là đã bật):

- Xóa phát hiện của **clamdscan** (process chính tự gộp sau khi worker trả về, từ 0.17.1) hay của VirusTotal (process
  chính tra và gộp).
- Thấy khóa API, token trong biến môi trường; thấy mật khẩu trên dòng lệnh.
- Làm process chính treo: output worker ghi ra file, không qua pipe (từ 0.17.1); hard timeout luôn kill worker.
- Chèn ký tự điều khiển vào terminal của bạn qua output của worker.
- Trên Linux x86_64: ghi ra ngoài thư mục tạm, đọc file cá nhân, mở bất kỳ socket nào, ptrace process khác.

Hệ quả: với file có thể nhắm vào chính bạn, hiểu SẠCH là "không thấy dấu hiệu", kết hợp thêm công cụ khác, và chạy
trên Linux x86_64 hoặc trong Docker với `--require-sandbox`.

## 7. Nếu threat intelligence API bị lỗi thì scanner xử lý thế nào?

| Nguồn | Khi lỗi | Ảnh hưởng tới kết luận |
|---|---|---|
| VirusTotal (`--virustotal`) | 429 → chờ 60 s thử lại một lần; lỗi khác → dừng tra phần còn lại, in cảnh báo | Không đổi: VirusTotal chỉ **thêm** phát hiện, không bao giờ làm file thành SẠCH |
| `--update-db` (Release `hash-db`) | Chữ ký sai, mất mạng, thiếu thư viện sigstore → mã 3, **giữ nguyên** cache cũ | Quét vẫn chạy với mã băm đi kèm gói + cache cũ |
| `--update-hashes` (abuse.ch) | Lỗi một họ → bỏ qua họ đó; lỗi mọi truy vấn hoặc Auth-Key sai → mã 3, giữ cache cũ | Như trên |
| ClamAV | Không chạy được, thiếu cơ sở dữ liệu, hết giờ → `CLAMAV_UNAVAILABLE` | **CHƯA QUÉT ĐỦ** (mã 4), trừ khi chạy `--no-clamav` |

Quét **không cần mạng**: mã băm đi kèm gói, luật YARA, heuristic và ClamAV cục bộ đều chạy offline.

## 8. Nếu một file vượt quá ngân sách thì kết quả cuối cùng là gì?

Không bao giờ là SẠCH. Dừng ngay tại chỗ chạm ngưỡng (giữa chừng một file con), không đọc thêm byte nào; phát hiện
vượt ngân sách được ghi đúng một lần, kèm mã lý do; phần đã quét vẫn được báo cáo.

| Vượt | Kết luận tối thiểu | Mã thoát mặc định |
|---|---|---|
| Số entry, tổng dung lượng, thời gian, độ sâu, tỷ lệ nén | ĐÁNG NGỜ (kỹ thuật làm hỏng trình quét), JSON ghi `complete: false` | 1 |
| Kích thước một file con | CHƯA QUÉT ĐỦ | 4 |
| Hard timeout của worker | CHƯA QUÉT ĐỦ (`WORKER_TIMEOUT`) | 4 |
| Worker crash / hết RAM / báo cáo không hợp lệ | Lỗi (`WORKER_ERROR`) | 3 |

Có phát hiện mạnh hơn (vd. mã băm độc trong phần đã quét) thì kết luận theo phát hiện đó.

## Mã lý do "chưa quét đủ"

Mỗi phần chưa kiểm tra được xuất hiện trong JSON ở hai trường song song: `incomplete` (chuỗi để đọc) và
`incomplete_reasons` (`{"code", "where", "detail"}` để máy xử lý). Danh sách mã (`scanner.REASONS`) chỉ được thêm,
không đổi nghĩa:

| Mã | Ý nghĩa |
|---|---|
| `ARCHIVE_TOO_LARGE` | file nén đầu vào lớn hơn `--max-archive-size` |
| `FILE_TOO_LARGE` | file (không phải file nén) lớn hơn `--max-size` |
| `CLAMAV_UNAVAILABLE` | ClamAV không chạy được hoặc hết giờ |
| `ENGINE_ERROR` | heuristic hoặc YARA lỗi trên một file |
| `UNSUPPORTED_FORMAT` | định dạng chứa file chưa giải nén được (CAB, ISO, VHD…) |
| `TOO_DEEP` | lồng quá `--max-depth` tầng |
| `BUDGET_FILES`, `BUDGET_BYTES`, `BUDGET_TIME` | vượt ngân sách số entry, dung lượng, thời gian |
| `ENCRYPTED_LISTING` | danh sách file bị mã hóa |
| `ARCHIVE_UNREADABLE` | file nén hỏng hoặc parser lỗi |
| `STRUCTURE_UNCHECKED` | không kiểm tra được cấu trúc ZIP (entry giấu, vùng chồng nhau) |
| `MEMBER_TOO_LARGE`, `MEMBER_ENCRYPTED`, `MEMBER_BOMB`, `MEMBER_UNREADABLE` | một file con không được đọc |
| `WORKER_ERROR`, `WORKER_TIMEOUT` | worker lỗi / bị dừng vì hard timeout |

## Ngoài phạm vi

- Mã độc không có dấu hiệu nào ArchiveGuard biết: đây là giới hạn phát hiện, đo bằng benchmark
  ([BENCHMARK.md](BENCHMARK.md)), không phải lỗ hổng.
- Lỗ hổng của trình giải nén **bạn** dùng sau khi quét: bước giải nén thật vẫn phải chống path traversal và giới hạn
  dung lượng.
- TOCTOU khi file bị thay sau khi quét: quét bản trong vùng cách ly và xử lý đúng bản đó.
- Kẻ tấn công đã kiểm soát máy chạy ArchiveGuard, cấu hình, hay tài khoản GitHub của người giữ repo.
