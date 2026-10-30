# Đo độ chính xác của ArchiveGuard

Tài liệu này ghi lại **những gì đã đo được**, **những gì chưa đo**, và **cách tự đo**. Mọi con số đều kèm
khoảng tin cậy 95% (Wilson), vì với vài chục đến vài trăm mẫu, một tỷ lệ đơn lẻ dễ gây hiểu lầm.

## Công cụ

```bash
python -m archive_guard.benchmark --malicious mau_doc/ --benign phan_mem_sach/ -p infected --out ketqua
```

- Mỗi file dưới hai thư mục là một mẫu. Thư mục con đầu tiên là **tên nhóm**: họ mã độc
  (`mau_doc/AgentTesla/…`) hoặc nhóm phần mềm sạch (`phan_mem_sach/thong-dung/…`).
- Kết quả: precision, recall, F1, tỷ lệ báo nhầm (FPR) ở hai ngưỡng (≥ ĐÁNG NGỜ và = NGUY HIỂM),
  recall theo họ, FPR theo nhóm, **danh sách từng ca báo nhầm và bỏ sót** kèm luật gây ra, xuất ra `.md` và `.json`.
- Mỗi kết quả ghi kèm phiên bản ArchiveGuard, `rules_version` (và từng thành phần), hệ điều hành, phiên bản
  Python, số CPU, thời gian trung vị/p95/max mỗi mẫu. Chỉ so sánh hai lần đo có cùng thành phần luật mà bạn
  không cố ý thay đổi.
- Kết quả được tách theo **lớp phát hiện**. Dòng **"Không dùng mã băm"** mô phỏng mã độc *mới*, chưa có trong
  danh sách mã băm. Đây là dòng phản ánh đúng năng lực heuristic, vì mẫu lấy từ MalwareBazaar gần như chắc chắn
  đã nằm trong danh sách mã băm, khiến dòng "Tất cả" cao một cách tự nhiên.

## Kết quả 1 – Báo nhầm trên phần mềm sạch (đã đo, 2026-10-30, bản 0.4.0)

**Bộ dữ liệu:** 109 file nén thật (585 MB, 22.209 file con) tải từ PyPI và npm, chủ yếu là bản Windows có
`.exe/.dll/.sys`. Danh sách và SHA-256 từng file: [`benchmark/benign-corpus.txt`](../benchmark/benign-corpus.txt).
Kết quả thô: [`benchmark/results-2026-10-30-benign.md`](../benchmark/results-2026-10-30-benign.md).

| Nhóm | Số mẫu | Bị gắn ≥ ĐÁNG NGỜ | Bị gắn NGUY HIỂM |
|---|---|---|---|
| **Phần mềm thông dụng** (numpy, pandas, cryptography, PyQt/PySide, pygame, esbuild, ruff…) | 93 | **8,6%** (KTC 95%: 4,4%–16,1%) | **0%** (0%–4,0%) |
| **Công cụ hai mặt**: hợp pháp nhưng làm đúng việc mã độc làm (hook bàn phím, tiêm tiến trình, terminal ẩn, kiểm thử xâm nhập: pynput, frida, pymem, impacket, AutoHotkey…) | 16 | 62,5% (38,6%–81,5%) | 6,2% (1,1%–28,3%) |
| Tất cả | 109 | 16,5% (10,7%–24,6%) | 0,9% (0,2%–5,0%) |

- **Lớp mã băm** (20.772 mã từ MalwareBazaar) gây **0** báo nhầm.
- Thời gian quét: trung vị 0,16 giây/mẫu, lâu nhất 25,7 giây (pyside6, file nén 78 MB).

**Ý nghĩa:** với phần mềm thông dụng, kết luận **NGUY HIỂM chưa sai lần nào** (cận trên 4%), còn
**ĐÁNG NGỜ thì cứ khoảng 12 gói có 1 gói bị gắn nhầm**. Vì vậy ĐÁNG NGỜ nên được hiểu là "cần xem lại", không phải "có mã độc".

### Nguyên nhân từng ca báo nhầm ở phần mềm thông dụng (8 ca)

| Mẫu | Luật | Nguyên nhân gốc | Loại lỗi |
|---|---|---|---|
| ruff, biome (trình biên dịch Rust) | `BACKDOOR.KNOWN_RAT` | Chuỗi `dcrat` (tên một họ RAT) khớp **bên trong** từ khác trong file nhị phân; luật không kiểm tra ranh giới từ | **Lỗi luật** – sửa được |
| esbuild | `RANSOM.NOTE` | `.onion` và "decryption key" là chuỗi bình thường trong thư viện mạng/mã hóa của Go | **Lỗi luật** – chuỗi quá chung chung |
| pygame (SDL2), pyside6 (Qt), wxpython | `KEYLOG.API` | Thư viện giao diện nào cũng đọc phím, cửa sổ đang mở và clipboard – đúng tổ hợp API của keylogger | Giới hạn bản chất của heuristic |
| pywin32 | `INJECT.PROCESS`, `KEYLOG.API`, `WORM.NETWORK` | Bọc gần như toàn bộ Windows API | Giới hạn bản chất |
| electron-winstaller (Squirrel) | `DOWNLOAD.API`, `PERSIST.AUTOSTART` | Bộ cập nhật tự động hợp pháp: tải bản mới và tự chạy khi khởi động | Giới hạn bản chất |

Ở nhóm công cụ hai mặt, 10/16 bị gắn cờ, chủ yếu vì `KEYLOG.API` và `INJECT.PROCESS`: chức năng chính của
các công cụ này *chính là* hook bàn phím hay tiêm mã. Ca NGUY HIỂM duy nhất là **impacket**, bộ công cụ kiểm thử
xâm nhập có chứa script trích xuất mật khẩu và xóa shadow copy. Heuristic không phân biệt được ý định, chỉ phân
biệt được khả năng.

### Hạn chế của phép đo này

- **Thiên lệch chọn mẫu:** chỉ có gói lập trình (PyPI/npm), chưa có phần mềm người dùng phổ thông (game, bộ cài
  ứng dụng, tài liệu Office/PDF), vốn là thứ hay được tải về dạng file nén.
- **n = 109:** khoảng tin cậy còn rộng; muốn cận trên dưới 1% cần khoảng 400 mẫu sạch liên tiếp không bị gắn cờ.
- **Bộ này đã được dùng để chỉnh luật** ở vòng 2 bên dưới, nên số liệu "sau khi sửa" trên bộ này bị thiên lệch.
  Số liệu khách quan là số đo trên bộ kiểm tra riêng.

## Vòng 2 – Sửa 2 lỗi luật, kiểm tra trên bộ chưa từng dùng (2026-10-31, bản 0.8.0)

**Hai thay đổi** (chỉ hai, đã chọn từ vòng 1 trước khi nhìn bộ kiểm tra):

1. `BACKDOOR.KNOWN_RAT`: tên họ mã độc chỉ được tính khi **đứng đầu một từ** (ký tự đứng trước không phải chữ/số;
   kiểm tra cả ASCII lẫn UTF-16 và cả ở ranh giới giữa hai khúc quét). Phía sau tên được tự do (`DcRatBuilder`).
2. `RANSOM.NOTE`: phải có **cả lời đòi tiền chuộc** ("your files have been encrypted", "decrypt your files"…)
   **lẫn cách trả tiền/liên lạc** (bitcoin, monero, .onion, Tor, decryptor…). Trước đây hai chuỗi bất kỳ trong một
   danh sách chung là đủ, nên `.onion` + "decryption key" trong thư viện mạng của esbuild bị gắn nhầm.

**Phương pháp:** dựng một **bộ kiểm tra mới** gồm 81 gói ([`benchmark/holdout-corpus-1.txt`](../benchmark/holdout-corpus-1.txt),
không trùng gói nào với bộ cũ), đo nó bằng **luật cũ trước**, rồi mới đo bằng luật mới. Bộ kiểm tra không được
dùng để chọn hay chỉnh thay đổi nào.

| Bộ dữ liệu | Nhóm | Trước (0.7.0) | Sau (0.8.0) |
|---|---|---|---|
| **Bộ kiểm tra mới** (khách quan) | Thông dụng, 71 gói | 11,3% (5,8–20,7%) | **4,2%** (1,4–11,7%) |
| | Thông dụng, gắn NGUY HIỂM | 0% | 0% (0–5,1%) |
| | Hai mặt, 10 gói | 30% | 30% |
| Bộ cũ (đã dùng để chỉnh, thiên lệch) | Thông dụng, 93 gói | 8,6% | 6,5% |
| | Hai mặt, 16 gói | 62,5% | 62,5% |

Kết quả thô: [`results-2026-10-31-holdout-before.md`](../benchmark/results-2026-10-31-holdout-before.md),
[`…-holdout-after.md`](../benchmark/results-2026-10-31-holdout-after.md),
[`…-benign-after.md`](../benchmark/results-2026-10-31-benign-after.md).

**Đọc kết quả cho đúng:**

- Trên bộ kiểm tra, **5/5 ca `KNOWN_RAT` biến mất** (uv, turbo, rspack, tauri, jiter: đều là file nhị phân Rust
  có chuỗi ghép kiểu `…ed` + `crates`). Đây là bằng chứng chính, vì cơ chế khớp đúng loại lỗi đã sửa.
- Với 71 mẫu, khoảng tin cậy trước và sau **vẫn chồng lên nhau**, nên riêng con số chưa đủ khẳng định về mặt thống kê.
- **Recall chưa đo** (xem Kết quả 2). Thay đổi chỉ được kiểm chứng bằng test: các mẫu thử có tên họ mã độc thật
  và thư đòi tiền chuộc thật vẫn bị bắt; một kiểu thư mới ("Send Monero to get the decryptor") trước bị sót, giờ bắt được.

**Còn tồn tại, để dành cho vòng sau** (cần một bộ kiểm tra thứ ba):

| Mẫu | Luật | Nguyên nhân |
|---|---|---|
| ruff (bộ cũ) | `BACKDOOR.KNOWN_RAT` | Chuỗi `#\d` + `crates` → `\dcrates`: `dcrat` đứng sau dấu `\` nên vẫn là "đầu từ". Tên `DcRat` quá ngắn; sửa triệt để cần so khớp phân biệt hoa/thường, có rủi ro làm sót mã độc nên chờ có số liệu recall |
| pip, virtualenv (bộ kiểm tra) | `BACKDOOR.REVERSE_SHELL` | `pty.spawn(` trong một đoạn ví dụ của thư viện `rich` mà pip đóng gói kèm. Cùng kiểu yếu điểm: luật mức HIGH dựa vào **một chuỗi đơn lẻ** |
| cmake, pygame, Qt, wxPython | `KEYLOG.API` | Thư viện giao diện dùng đúng tổ hợp API của keylogger; giới hạn bản chất của heuristic |

## Kết quả 2 – Phát hiện mã độc thật (recall): **CHƯA ĐO**

Đây là con số quan trọng nhất và hiện **chưa có**. Lý do: môi trường phát triển không tải được mẫu mã độc,
và việc đó chỉ nên làm trong máy ảo cách ly. Trước khi có số liệu, mọi nhận định về khả năng phát hiện
mã độc bị **obfuscate, pack, mã hóa hoặc chưa có chữ ký** đều chỉ là suy luận từ cơ chế hoạt động:

| Tình huống | Dự đoán (chưa kiểm chứng) | Lý do |
|---|---|---|
| Mẫu đã có trên MalwareBazaar | Gần 100% | Trùng mã băm |
| Mã độc mới, không pack, dạng script hoặc .exe | Trung bình | Chuỗi API/hành vi còn lộ |
| Mã độc bị pack (UPX, Themida…) | Chỉ ở mức ĐÁNG NGỜ | Chỉ biết là "đã pack", không biết bên trong làm gì |
| Mã độc .NET bị obfuscate, payload tải về lúc chạy, macro Office | Thấp | Chuỗi bị giấu; không có phân tích động |

### Cách tự đo recall (khoảng 1–2 giờ)

> ⚠️ Chỉ làm trong **máy ảo cách ly**: không thư mục chia sẻ, không đăng nhập tài khoản cá nhân, chụp snapshot
> trước và khôi phục sau khi xong. ArchiveGuard không chạy file nào, nhưng bản thân các mẫu là mã độc thật.

1. **Lấy mẫu:** dùng API MalwareBazaar (cùng Auth-Key với `--update-hashes`), truy vấn `get_siginfo` cho mỗi họ
   rồi `get_file` theo SHA-256. Mẫu được trả về dạng ZIP mật khẩu `infected`. Nên lấy khoảng **30–50 mẫu mỗi họ**
   cho các họ trong `archive_guard/malwarebazaar.py`, cộng vài họ ngoài danh sách đó để thử với mã độc
   "lạ". Ưu tiên mẫu có `first_seen` **sau** ngày của file `archive_guard/data/malwarebazaar.txt`, để cả lớp
   mã băm cũng được thử với mẫu mới.
2. **Sắp xếp:** `mau_doc/<Họ>/<sha256>.zip`, giữ nguyên file ZIP mật khẩu (ArchiveGuard tự mở bằng `-p infected`).
   Đặt bộ phần mềm sạch vào `phan_mem_sach/<nhóm>/`.
3. **Chạy:**

   ```bash
   python -m archive_guard.benchmark --malicious mau_doc --benign phan_mem_sach -p infected --out ketqua
   ```

4. **Đọc kết quả:** xem dòng **"Không dùng mã băm"** để biết năng lực với mã độc mới, bảng recall theo họ để
   biết họ nào bị bỏ sót, và danh sách bỏ sót để biết cần thêm luật gì. Chỉ gửi lại file `ketqua.md`/`ketqua.json`
   (chỉ chứa tên file và mã băm), **không** gửi mẫu.

## Tái hiện kết quả 1

Mọi gói trong `benchmark/benign-corpus.txt` đều tải được công khai:
`pip download --no-deps --only-binary=:all: --platform win_amd64 --python-version 3.12 <tên>==<phiên bản>`
cho file `.whl`, và `npm pack <tên>@<phiên bản>` cho file `.tgz`. Sau đó đối chiếu SHA-256, đặt vào
`phan_mem_sach/common/` hoặc `phan_mem_sach/dual-use/` như trong danh sách, rồi chạy công cụ với `--benign`.
