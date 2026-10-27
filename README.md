# ArchiveGuard 🛡️

[![tests](https://github.com/nakame9/archive-guard/actions/workflows/tests.yml/badge.svg)](https://github.com/nakame9/archive-guard/actions/workflows/tests.yml)

Công cụ dòng lệnh quét **file nén (ZIP, RAR, 7z, TAR, GZ, BZ2, XZ)** để tìm dấu hiệu mã độc như
**trojan, keylogger, worm, ransomware, stealer, backdoor/RAT, downloader** – trước khi bạn giải nén
hay mở bất cứ thứ gì bên trong.

> ⚠️ ArchiveGuard là công cụ **hỗ trợ phát hiện**, không thay thế phần mềm diệt virus. Kết quả
> "SẠCH" chỉ có nghĩa là không thấy dấu hiệu nguy hiểm, không phải bảo đảm an toàn tuyệt đối.

## Tính năng

- **Không bao giờ giải nén ra đĩa** – mọi thứ được đọc trong bộ nhớ, nên file độc hại kiểu
  `../../Windows/evil.exe` (Zip Slip) không thể ghi đè gì cả.
- **Đi vào file nén lồng nhau** (zip trong rar trong 7z…), có giới hạn độ sâu.
- **Chống zip bomb**: giới hạn dung lượng mỗi file, tổng dung lượng giải nén, số file và tỷ lệ nén.
- **Hỗ trợ file có mật khẩu** (`--password`), và cảnh báo khi file thực thi bị khóa mật khẩu –
  thủ thuật phổ biến để né antivirus.
- **Nhiều lớp phát hiện:**

| Lớp | Phát hiện |
|---|---|
| Tên file | đuôi kép `hoadon.pdf.exe`, ký tự đảo chiều Unicode (RLO), chèn khoảng trắng giấu đuôi, `.scr/.hta/.lnk/.iso…`, `autorun.inf`, Zip Slip, symlink nguy hiểm |
| Nội dung | file `.exe` đội lốt `.pdf/.jpg`, macro VBA trong tài liệu Office |
| Hành vi (chuỗi ASCII + UTF-16) | keylogger (hook bàn phím, nhãn `[BACKSPACE]`…), tiêm mã tiến trình, tự khởi động, tải & chạy mã (PowerShell/VBS dropper), tắt Defender/AMSI, chống máy ảo, xóa shadow copy & thư đòi tiền chuộc (ransomware), đánh cắp mật khẩu trình duyệt/ví tiền ảo, gửi dữ liệu qua Telegram/Discord, reverse shell, lây lan qua USB/mạng (worm) |
| Mã băm | so với danh sách MD5/SHA1/SHA256 mã độc đã biết (mở rộng bằng `--hashes`) |
| YARA *(tùy chọn)* | luật đi kèm + luật của bạn (`--yara`) |
| ClamAV *(tùy chọn)* | nếu máy có `clamscan`/`clamdscan`, tự động dùng thêm engine chữ ký của ClamAV |

## Cài đặt

Cần Python 3.10 trở lên.

```bash
git clone https://github.com/nakame9/archive-guard.git
cd archive-guard
pip install -e .            # bản cơ bản
pip install -e ".[yara]"    # thêm YARA (khuyên dùng)
```

Tùy chọn thêm:

- **Đọc nội dung RAR**: cần `unrar` hoặc `7z` trong PATH (Windows: cài 7-Zip rồi thêm
  `C:\Program Files\7-Zip` vào PATH; Ubuntu: `sudo apt install unrar`). Không có thì vẫn kiểm tra được tên file trong RAR.
- **ClamAV**: Ubuntu `sudo apt install clamav && sudo freshclam`; Windows tải tại clamav.net.

## Sử dụng

```bash
archiveguard file.zip                       # quét một file
archiveguard Downloads/                     # quét mọi file nén trong thư mục
archiveguard tailieu.rar -p 123456 -p infected   # thử các mật khẩu
archiveguard file.7z --all                  # liệt kê cả file sạch
archiveguard file.zip --json baocao.json    # xuất báo cáo JSON
archiveguard file.zip --yara my_rules/ --hashes malware_sha256.txt
python -m archive_guard file.zip            # chạy không cần cài
```

Ví dụ kết quả (file mẫu vô hại tạo trong lúc thử nghiệm):

```text
== hoa-don-thang-10.zip ==
  [NGUY HIỂM 100] hoa-don-thang-10.zip > HoaDon_T10.pdf.exe
      HIGH     Trojan / ngụy trang: Đuôi kép giả mạo: trông như .pdf nhưng thực ra là .exe
               HoaDon_T10.pdf.exe
      HIGH     Keylogger (ghi phím): Chứa nhãn ghi phím đặc trưng của keylogger
               khớp: [backspace], [capslock], [enter]
      MEDIUM   Keylogger (ghi phím): Dùng API bắt phím kèm theo dõi cửa sổ/clipboard
               khớp: getforegroundwindow, setwindowshookexa
      MEDIUM   Stealer (đánh cắp dữ liệu): Gửi dữ liệu ra ngoài qua Telegram bot / Discord webhook / SMTP
               khớp: api.telegram.org/bot
      LOW      Đáng chú ý: Có file thực thi/script .exe
      LOW      Trojan / ngụy trang: Tự khởi động cùng Windows (Run key, Startup, tác vụ lập lịch)
               khớp: currentversion\run
  [ĐÁNG NGỜ 30] hoa-don-thang-10.zip > autorun.inf
      MEDIUM   Worm (tự lây lan): autorun.inf – cơ chế tự chạy mà worm USB hay dùng
  Đã quét 4 file: 1 nguy hiểm, 1 đáng ngờ, 2 sạch
  KẾT LUẬN: NGUY HIỂM – dấu hiệu: Keylogger (ghi phím), Stealer (đánh cắp dữ liệu), Trojan / ngụy trang, Worm (tự lây lan)
```

**Mã thoát** (dùng được trong script/CI): `0` sạch · `1` đáng ngờ · `2` nguy hiểm · `3` lỗi.

## Cách chấm điểm

Mỗi phát hiện có mức độ `LOW` (10) · `MEDIUM` (30) · `HIGH` (60) · `CRITICAL` (100) và thuộc một nhóm
hành vi (keylogger, worm…). Điểm của một file = tổng mức **nặng nhất của từng nhóm** (tối đa 100), nên nhiều
bằng chứng cho cùng một hành vi không bị cộng dồn, còn nhiều hành vi khác nhau thì cộng lại.

| Điểm | Kết luận |
|---|---|
| < 30 | SẠCH |
| 30 – 79 | ĐÁNG NGỜ |
| ≥ 80, hoặc có phát hiện CRITICAL (trùng mã băm, ClamAV, YARA critical) | NGUY HIỂM |

## Mở rộng

**Thêm luật YARA** – bỏ file `.yar` vào `archive_guard/data/rules/` hoặc dùng `--yara`. Phần `meta` quyết định điểm:

```yara
rule My_Keylogger {
    meta:
        description = "Keylogger viết bằng Python"
        severity = "high"          // low | medium | high | critical
        category = "keylogger"
    strings:
        $a = "pynput.keyboard"
        $b = "smtplib"
    condition:
        all of them
}
```

Bộ luật cộng đồng nên thử: [Yara-Rules/rules](https://github.com/Yara-Rules/rules),
[Neo23x0/signature-base](https://github.com/Neo23x0/signature-base).

**Thêm mã băm mã độc** – tạo file text mỗi dòng một mã MD5/SHA1/SHA256 (dòng `#` là chú thích), rồi chạy
`--hashes file.txt`. Có thể dùng danh sách export từ [MalwareBazaar](https://bazaar.abuse.ch/).

**Thêm chỉ dấu hành vi** – sửa danh sách `_INDICATORS` trong `archive_guard/rules.py`.

## Cấu trúc dự án

```text
archive_guard/
├── cli.py          # dòng lệnh, in báo cáo, xuất JSON
├── scanner.py      # điều phối quét, đệ quy file nén, chấm điểm
├── extract.py      # đọc ZIP/RAR/7z/TAR/GZ trong bộ nhớ, giới hạn chống zip bomb
├── rules.py        # luật tên file, loại file, chỉ dấu hành vi, danh sách mã băm
├── engines.py      # YARA và ClamAV (tùy chọn)
└── data/
    ├── known_bad.txt   # mã băm mã độc đã biết
    └── rules/*.yar     # luật YARA đi kèm
tests/test_scanner.py   # test – mọi mẫu thử được tạo trong bộ nhớ
```

## Chạy test

```bash
pip install -e ".[yara,dev]"
pytest -q
```

Test dùng chuỗi **EICAR** (file thử nghiệm antivirus chuẩn, vô hại) và các "mẫu giả" chỉ chứa chuỗi văn bản,
tất cả tạo trong bộ nhớ – repo không chứa mã độc thật.

## Giới hạn cần biết

- Phát hiện dựa trên heuristic nên **có thể báo nhầm**: thư viện hợp pháp làm việc với Windows API
  (vd. `pywin32`, `pynput`) dùng chính các hàm mà keylogger/trojan dùng và sẽ bị đánh dấu ĐÁNG NGỜ.
- **Có thể bỏ sót** mã độc bị nén/mã hóa bằng packer (UPX, Themida…) vì chuỗi bị giấu đi. Bật ClamAV/YARA để tăng độ phủ.
- Chỉ dò chuỗi trong 32 MB đầu + 4 MB cuối của mỗi file để giữ tốc độ.
- Quét chính repo này sẽ ra NGUY HIỂM, vì `rules.py` và file test chứa đúng các chuỗi cần dò (chuyện thường gặp với mọi bộ luật antivirus).
- Chưa phân tích sâu PDF và macro Office (chỉ phát hiện có macro), chưa mở RAR mã hóa cả tên file.

## Thử nghiệm an toàn

Nếu muốn thử với mẫu mã độc thật (vd. từ MalwareBazaar), **chỉ làm trong máy ảo không có dữ liệu cá nhân**.
ArchiveGuard không chạy file nào, nhưng chính file mẫu vẫn nguy hiểm nếu bị mở nhầm.

## Đóng góp

Pull request luôn được chào đón: thêm chỉ dấu, luật YARA, định dạng nén mới, hoặc báo nhầm/bỏ sót kèm mô tả.
Đừng đính kèm mã độc thật vào issue – hãy gửi mã băm SHA256.

## Giấy phép

[MIT](LICENSE). Công cụ chỉ dùng cho mục đích phòng thủ và học tập.
