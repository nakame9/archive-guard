# Hướng dẫn sử dụng

## Cài thêm

| Thành phần | Để làm gì | Cài thế nào |
|---|---|---|
| YARA | Chạy luật YARA đi kèm và luật của bạn | `pip install -e ".[yara]"` |
| `unrar` hoặc `7z` | Đọc **nội dung** file RAR (không có thì vẫn kiểm tra được tên file) | Windows: cài 7-Zip, thêm `C:\Program Files\7-Zip` vào PATH. Ubuntu: `sudo apt install unrar` |
| ClamAV | Thêm engine chữ ký (cần ~1–1,5 GB RAM) | Ubuntu: `sudo apt install clamav && sudo freshclam`. Windows: clamav.net |

Máy cài ClamAV nhưng **thiếu cơ sở dữ liệu chữ ký** sẽ nhận `CHƯA QUÉT ĐỦ` cho mọi file: chạy `freshclam`
hoặc dùng `--no-clamav`.

## Tùy chọn

```bash
archiveguard <file hoặc thư mục>... [tùy chọn]
python -m archive_guard <file>...           # chạy không cần cài
```

Thư mục được quét đệ quy; chỉ file có **chữ ký** của file nén (không dựa vào đuôi file) mới được quét.

| Nhóm | Tùy chọn | Mặc định | Ý nghĩa |
|---|---|---|---|
| Đầu vào | `-p, --password` | – | Mật khẩu thử cho file nén (lặp lại được) |
| Đầu ra | `--json FILE` | – | Ghi báo cáo chi tiết ra JSON |
| | `-a, --all` | tắt | Liệt kê cả file sạch |
| | `--no-color` | – | Tắt màu (cũng tắt khi có biến môi trường `NO_COLOR`) |
| Luật | `--yara PATH` | – | Thêm file/thư mục luật YARA (lặp lại được) |
| | `--hashes FILE` | – | Thêm danh sách mã băm mã độc (lặp lại được) |
| | `--no-yara`, `--no-clamav` | – | Tắt engine tương ứng |
| Mã băm | `--update-hashes` | – | Tải mã băm theo họ từ MalwareBazaar (xem bên dưới) |
| | `--auth-key KEY` | `$ABUSECH_AUTH_KEY` | Auth-Key của abuse.ch |
| Giới hạn | `--max-archive-size MB` | 4096 | Kích thước file nén đầu vào |
| | `--max-size MB` | 256 | Dung lượng mỗi file con được đọc |
| | `--max-total MB` | 4096 | Tổng byte giải nén, tính cả các tầng lồng nhau |
| | `--max-depth N` | 5 | Số tầng file nén lồng nhau |
| | `--timeout GIÂY` | 300 | Thời gian quét mỗi file nén |
| Cô lập | *(mặc định)* | bật | Mỗi file nén quét trong một worker có sandbox |
| | `--worker-timeout GIÂY` | `--timeout` + 30 | Hard timeout của worker (cũng là giới hạn CPU) |
| | `--worker-memory MB` | – | Giới hạn RAM cho worker (Linux, Windows) |
| | `--require-sandbox` | tắt | Từ chối quét nếu thiếu sandbox file/mạng |
| | `--no-sandbox`, `--no-isolate` | – | Tắt sandbox / tắt cả worker (xem bên dưới) |

Ngoài ra có hai giới hạn cố định: tổng **20.000 entry** (kể cả thư mục) và tỷ lệ nén **100:1** với file con từ 50 MB.

## Kết luận và mã thoát

| Kết luận | JSON `verdict` | Mã thoát | Ý nghĩa |
|---|---|---|---|
| SẠCH | `clean` | `0` | Đã kiểm tra **toàn bộ** nội dung và không thấy dấu hiệu nguy hiểm |
| CHƯA QUÉT ĐỦ | `incomplete` | `4` | Không thấy dấu hiệu nguy hiểm, nhưng **có phần chưa kiểm tra được**: file có mật khẩu, file nén hỏng, định dạng chưa hỗ trợ (CAB, ISO, WIM, Zstandard…), engine lỗi/timeout, vượt giới hạn. **Không được coi là sạch** |
| ĐÁNG NGỜ | `suspicious` | `1` | Có dấu hiệu cần xem lại |
| NGUY HIỂM | `malicious` | `2` | Có dấu hiệu mạnh hoặc trùng mã độc đã biết |

Mã `3` là lỗi (không đọc được file, worker crash, lỗi ngoài dự kiến). Lỗi xử lý **không bao giờ** cho ra SẠCH.
Khi vừa có dấu hiệu nguy hiểm vừa có phần chưa quét, kết luận theo dấu hiệu và kèm ghi chú `CHƯA ĐẦY ĐỦ`.
Quét nhiều file thì mã thoát là của kết luận nặng nhất. Cách tính điểm: [RULES.md](RULES.md).

## Báo cáo JSON

```json
{"schema_version": 1, "version": "0.11.0", "rules_version": "2e803535739a",
 "rules_components": {"heuristic": "…", "yara": "…", "hashes": "…", "all": "2e803535739a"},
 "engines": {…}, "isolation": null,
 "reports": [{"target": "…", "verdict": "incomplete", "complete": false, "incomplete": […], "files": […]}]}
```

- `schema_version` (hiện là `1`): chỉ tăng khi một trường bị đổi tên, xóa hoặc đổi nghĩa. Thêm trường mới thì giữ
  nguyên, nên công cụ đọc báo cáo cứ bỏ qua trường lạ là tương thích. Test `tests/test_cli.py` khóa các trường của bản 1.
- `rules_version`: mã 12 ký tự **tự sinh từ nội dung bộ luật**. Cùng bộ luật thì cùng mã trên mọi máy;
  `rules_components` cho biết phần nào đã đổi. Danh sách mã băm cập nhật hằng tuần nên mã này cũng đổi hằng tuần.
- `complete` / `incomplete`: có phần nào chưa kiểm tra được không, và cụ thể là phần nào.
- `sandbox` (mỗi báo cáo): các lớp sandbox worker đã bật; `isolation` (đầu file): cấu hình cô lập, `null` khi `--no-isolate`.
- `worker_error`: lý do worker thất bại (nếu có).

## Cô lập và sandbox (mặc định)

Parser file nén **không chạy trong process chính**. Mỗi file nén được quét trong một **process con (worker)**:
process chính chỉ canh giờ, đọc và kiểm tra kết quả, dọn dẹp. Worker tự áp **sandbox hệ điều hành** ngay sau khi
nạp bộ luật và **trước khi đọc byte đầu tiên** của file cần quét; process con của nó (unrar, clamscan) thừa hưởng
mọi hạn chế. Worker treo, crash, hết RAM hay trả kết quả hỏng → `CHƯA QUÉT ĐỦ` (hết giờ, mã 4) hoặc lỗi
(mã 3), **không bao giờ là SẠCH**; JSON ghi `worker_error`.

| Lớp bảo vệ | Linux | macOS | Windows |
|---|---|---|---|
| Hard timeout `--worker-timeout` (mặc định `--timeout` + 30 s), kill **cả cây** process | ✅ process group | ✅ process group | ✅ Job Object |
| Giới hạn CPU (= hard timeout) | ✅ RLIMIT_CPU | ✅ RLIMIT_CPU | ✅ Job Object |
| Giới hạn RAM `--worker-memory` (worker + process con) | ✅ RLIMIT_AS | ❌ báo lỗi | ✅ Job Object |
| Thư mục tạm riêng, xóa khi xong | ✅ | ✅ | ✅ |
| Chỉ **ghi** được thư mục tạm riêng | ✅ Landlock | ✅ sandbox-exec | ❌ |
| Chỉ **đọc** được file đầu vào + thư viện + thư mục hệ thống | ✅ Landlock | ❌ (đọc được mọi file) | ❌ |
| Chặn mạng | ✅ network namespace / seccomp / Landlock TCP | ✅ sandbox-exec | ❌ |
| Chặn syscall nguy hiểm (ptrace, mount, bpf, nạp module…) | ✅ seccomp (x86_64) | ❌ | ❌ |
| no_new_privs, không ghi core dump | ✅ | – | – |
| Mật khẩu truyền qua stdin, không lộ trên dòng lệnh | ✅ | ✅ | ✅ |

Cuối mỗi lần quét, dòng `Sandbox của worker: …` (và trường `sandbox` của mỗi báo cáo JSON) cho biết **lớp nào
thực sự đã bật** trên máy bạn. Kiểm tra nhanh: `python -m archive_guard.sandbox` chạy thử các thao tác bị cấm
(ghi ra ngoài, đọc file cá nhân, mở socket, ptrace) trong sandbox và in kết quả.

| Tùy chọn | Khi nào dùng |
|---|---|
| `--require-sandbox` | **Production:** từ chối quét (mã 3) nếu worker không giới hạn được truy cập file **và** chặn được mạng. Trên Windows luôn từ chối: hãy dùng Docker hoặc WSL |
| `--no-sandbox` | Vẫn dùng worker nhưng không áp sandbox (khi sandbox làm hỏng một môi trường lạ) |
| `--no-isolate` | **Không khuyến khích với dữ liệu không tin cậy:** parser chạy ngay trong process chính, không hard timeout, không sandbox; nhanh hơn ~0,1 giây mỗi file nén |

Ghi chú:
- Chi phí của worker khoảng **0,1 giây mỗi file nén**.
- `--worker-memory` thấp hơn ~1,5 GB thì ClamAV không chạy được và kết quả là `CHƯA QUÉT ĐỦ`.
- Network namespace cần user namespace không đặc quyền; container (vd. Docker) và hệ thống có chính sách hạn chế
  user namespace sẽ không cho phép. Khi đó mạng vẫn bị chặn bằng seccomp (mọi socket không phải AF_UNIX) và Landlock
  (TCP). Đã kiểm chứng trên CI: máy Linux bật đủ 4 lớp; trong Docker bật tất cả trừ network namespace.
- Landlock cần kernel ≥ 5.13 có bật Landlock. seccomp hiện chỉ cho x86_64.
- `python -m archive_guard.benchmark` vẫn chạy parser trong process của nó: chỉ dùng trong máy ảo (xem BENCHMARK.md).

### Docker

Lớp ngoài cùng cho production: container không mạng, hệ thống file chỉ đọc, không capability, không leo quyền,
giới hạn RAM và số process. Sandbox của worker vẫn hoạt động **bên trong** container.

```bash
docker build -t archive-guard .
docker run --rm --network none --read-only --tmpfs /tmp:rw,size=1g --cap-drop ALL \
  --security-opt no-new-privileges --memory 2g --pids-limit 128 \
  -v "$PWD:/scan:ro" archive-guard .
```

Image chạy bằng user thường (uid 10001), thư mục cần quét được gắn **chỉ đọc** vào `/scan`. Image không có
ClamAV và `unrar` (thêm vào Dockerfile nếu cần). `--update-hashes` cần mạng, nên hãy build lại image để có danh
sách mã băm mới.

## Mã băm mã độc từ MalwareBazaar

Repo kèm sẵn `archive_guard/data/malwarebazaar.txt` (khoảng 20.000 mã), được workflow `update-hashes` tự tải từ
[MalwareBazaar](https://bazaar.abuse.ch/) và commit **mỗi thứ Hai**. Chỉ cần `git pull` là có danh sách mới.
Nếu bạn fork repo, thêm secret `ABUSECH_AUTH_KEY` (Settings → Secrets and variables → Actions).

Muốn cập nhật ngay trên máy (lưu vào cache riêng, gộp chung khi quét):

```bash
# Đăng ký Auth-Key miễn phí tại https://auth.abuse.ch/
export ABUSECH_AUTH_KEY=khoa_cua_ban            # PowerShell: $env:ABUSECH_AUTH_KEY = "khoa_cua_ban"
archiveguard --update-hashes                    # chỉ cập nhật
archiveguard --update-hashes Downloads/         # cập nhật rồi quét luôn
```

Mỗi lần tải: mẫu đã gắn họ trong **7 ngày gần nhất**, cộng tối đa **1000 mẫu mới nhất cho mỗi họ** dưới đây.
Cache được **gộp dần** (không xóa mã cũ) tại `~/.cache/archive-guard/malwarebazaar.txt`
(Windows: `%LOCALAPPDATA%\archive-guard\malwarebazaar.txt`). Chỉ mã băm được tải về, không có mẫu mã độc nào.

| Nhóm | Họ mã độc |
|---|---|
| Keylogger | AgentTesla, SnakeKeylogger, Formbook |
| Stealer | LummaStealer, RedLineStealer, Vidar, Stealc |
| Backdoor / RAT | RemcosRAT, AsyncRAT, XWorm, njrat, QuasarRAT, NanoCore, DCRat |
| Downloader | GuLoader, SmokeLoader, Amadey |
| Ransomware | LockBit |
| Worm | Phorpiex, Mirai |

## Giới hạn cần biết

**Phát hiện**
- Heuristic **có thể báo nhầm**: thư viện hợp pháp làm việc với Windows API (vd. `pywin32`, `pynput`) dùng chính
  các hàm mà keylogger/trojan dùng. Số liệu đo: [BENCHMARK.md](BENCHMARK.md).
- File bị pack chỉ được **cảnh báo là đã pack**; chuỗi hành vi bên trong vẫn bị giấu. Phần mềm hợp pháp dùng
  Themida/VMProtect cũng bị báo ĐÁNG NGỜ; UPX đơn thuần chỉ ở mức LOW.
- Mã băm chỉ bắt được **đúng** mẫu đã có trên MalwareBazaar: đổi một byte là mã băm khác.
- Chưa phân tích sâu PDF và macro Office (chỉ phát hiện có macro), chưa mở RAR mã hóa cả tên file.
- Quét chính repo này sẽ ra NGUY HIỂM, vì `rules.py` và test chứa đúng các chuỗi cần dò.

**Tài nguyên**
- RAM đỉnh trường hợp xấu nhất xấp xỉ `--max-depth × --max-size` (mỗi tầng lồng giữ nội dung tầng cha), tức
  khoảng 1,3 GB với mặc định. Máy yếu nên hạ `--max-size`.
- 7z và RAR: thư viện đọc **cả danh mục file** khi mở nên giới hạn số entry chỉ có hiệu lực ngay sau đó. Một file
  7z có danh mục khổng lồ vẫn tốn RAM lúc mở; dùng `--worker-memory` để chặn.
- Hạn `--timeout` bên trong worker là hợp tác (kiểm tra sau mỗi khúc 1 MB và giữa các file con); thao tác bị treo
  trong thư viện C hay parser bị crash chỉ được chặn bởi **hard timeout của process cha** – lý do parser không
  bao giờ chạy trong process chính, trừ khi bạn dùng `--no-isolate`.
- ClamAV không quét file trên 2 GB. Nếu dùng `clamdscan`, hãy tự nâng `MaxFileSize`/`MaxScanSize` trong
  `clamd.conf` (mặc định chỉ 100 MB).

## Thử nghiệm an toàn

Nếu muốn thử với mẫu mã độc thật (vd. từ MalwareBazaar), **chỉ làm trong máy ảo không có dữ liệu cá nhân**.
ArchiveGuard không chạy file nào, nhưng chính file mẫu vẫn nguy hiểm nếu bị mở nhầm.
