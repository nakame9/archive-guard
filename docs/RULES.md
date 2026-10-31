# Luật phát hiện và cách chấm điểm

## Cách chấm điểm

Mỗi phát hiện (finding) có ba thuộc tính độc lập:

| Thuộc tính | Trả lời câu hỏi | Giá trị |
|---|---|---|
| **severity** (mức độ) | Nếu đúng là mã độc thì nguy hại tới đâu? | `LOW` 10 · `MEDIUM` 30 · `HIGH` 60 · `CRITICAL` 100 điểm |
| **confidence** (độ tin cậy) | Chắc chắn tới đâu rằng đây là **hành vi độc hại**, không phải phần mềm hợp pháp? | `low` · `medium` · `high` |
| **attack** | Kỹ thuật tương ứng trong [MITRE ATT&CK](https://attack.mitre.org) | vd. `T1056.001` |

Tách hai trục này vì `SetWindowsHookExA` có severity cao (keylogger thì nguy hại) nhưng confidence thấp
(thư viện bàn phím, game, AutoHotkey… đều gọi nó).

### Khả năng và hành vi

- **Khả năng** (`confidence: low`): API/chuỗi mà phần mềm hợp pháp cũng dùng – `KEYLOG.API`, `INJECT.PROCESS`,
  `DOWNLOAD.API`, `PERSIST.AUTOSTART`, `EVADE.ANTI_VM`, `EXFIL.CHANNEL`, `WORM.NETWORK`, `PACKER.NAME` (UPX),
  `NAME.EXECUTABLE`. **Một mình không làm file bị gắn cờ.**
- **Hành vi** (`medium`/`high`): dấu hiệu cụ thể, hoặc **luật ngữ cảnh** đòi khả năng đi kèm bằng chứng bổ trợ
  trong **cùng một file** – đúng chuỗi kỹ thuật mà mã độc cần để đạt mục đích:

| Luật ngữ cảnh | Cần | ATT&CK |
|---|---|---|
| `KEYLOG.EXFIL` | API bắt phím **và** kênh gửi dữ liệu ra ngoài (Telegram bot, Discord webhook, SMTP…) | T1056.001 + T1567 |
| `STEAL.EXFIL` | đọc mật khẩu trình duyệt/ví tiền ảo **và** kênh gửi ra ngoài | T1555 + T1567 |
| `INJECT.LOADER` | API tiêm mã **và** né máy ảo hoặc tải payload | T1055 + T1497/T1105 |
| `BACKDOOR.REVERSE_SHELL` | mở shell **và** kết nối mạng (`pty.spawn(` một mình không đủ) | T1059 |

Bảng phân loại đầy đủ: `RULE_META` trong `archive_guard/rules.py`.

### Từ phát hiện tới kết luận (cho từng file)

1. **Lọc khả năng đơn lẻ:** nếu file chỉ có phát hiện `low` và chúng thuộc **dưới 3 nhóm hành vi khác nhau**
   (`CAPABILITY_MIN_CATEGORIES`) → không tính, file SẠCH. Ba nhóm khả năng khác nhau trong một file (vd. bắt phím
   + tự khởi động + tải file) thì được tính.
2. **Điểm** = tổng mức nặng nhất của **từng nhóm hành vi**, +30 nếu một nhóm có ≥ 2 luật medium/high khác nhau
   (tối đa 100). Nhiều chuỗi cho **cùng** một luật không cộng dồn.
3. **Kết luận:**

| Điều kiện | Kết luận |
|---|---|
| Có phát hiện `CRITICAL` với confidence `high` (trùng mã băm, ClamAV, YARA critical) | NGUY HIỂM |
| Điểm ≥ 80 **và** ≥ 2 bằng chứng độc lập: luật medium/high khác nhau, mỗi nhóm khả năng đi kèm tính ½ | NGUY HIỂM |
| Điểm ≥ 30 | ĐÁNG NGỜ |
| Còn lại | SẠCH |

Một luật HIGH đơn lẻ (vd. chỉ có lệnh tắt Defender) dừng ở ĐÁNG NGỜ: NGUY HIỂM luôn cần nhiều chỉ dấu độc lập.

Ngưỡng `CAPABILITY_MIN_CATEGORIES = 3` được hiệu chỉnh trên hai bộ phần mềm sạch đã dùng để chỉnh luật (190 gói):
file chỉ có khả năng ở đó có **tối đa 2** nhóm (bộ cập nhật Squirrel: tải file + tự khởi động), nên ngưỡng đặt
cao hơn 1. Mọi giá trị 2–99 cho cùng số báo nhầm trên hai bộ này; giá trị thấp nhất có biên an toàn được chọn để giữ
recall. Số liệu: [BENCHMARK.md](BENCHMARK.md#vòng-3--tách-khả-năng-và-hành-vi-2026-10-31-bản-0120).

Không có dấu hiệu nhưng có phần chưa kiểm tra được → `CHƯA QUÉT ĐỦ` (xem [USAGE.md](USAGE.md#kết-luận-và-mã-thoát)).
Kết luận của cả file nén là kết luận nặng nhất trong các file bên trong. Code: `score_and_verdict()` trong
`archive_guard/scanner.py`.

## Các lớp phát hiện

| Lớp | Phát hiện | Code |
|---|---|---|
| Tên file | đuôi kép `hoadon.pdf.exe`, ký tự đảo chiều Unicode, chèn khoảng trắng giấu đuôi, `.scr/.hta/.lnk/.iso…`, `autorun.inf`, Zip Slip, symlink nguy hiểm | `check_name()` |
| Nội dung | `.exe` đội lốt `.pdf/.jpg`, macro VBA, định dạng chứa file chưa hỗ trợ | `check_content()`, `file_kind()` |
| Packer | tên section UPX/ASPack/Themida/VMProtect/MPRESS/NsPack/Enigma/PECompact…, dấu `UPX!`, entropy > 7.2 ở vùng mã | `check_packer()` |
| Hành vi | 24 luật chỉ dấu (khả năng + luật ngữ cảnh), chuỗi ASCII + UTF-16, quét **trọn** file theo khúc 8 MB | `_INDICATORS`, `RULE_META` |
| Mã băm | MalwareBazaar theo họ + danh sách riêng (`--hashes`) | `load_hashes()`, `malwarebazaar.py` |
| YARA | `archive_guard/data/rules/*.yar` + `--yara` | `engines.py` |
| ClamAV | nếu máy có `clamscan`/`clamdscan` | `engines.py` |

Trừ YARA/ClamAV/mã băm, mọi luật nằm trong `archive_guard/rules.py`.

## Thêm chỉ dấu hành vi

Mỗi dòng trong `_INDICATORS` (file `archive_guard/rules.py`):

```python
("MÃ.LUẬT", MỨC_ĐỘ, "nhóm", "Mô tả hiển thị",
 [["chuỗi nhóm A", …], ["chuỗi nhóm B", …]],   # các nhóm chuỗi
 số_nhóm_phải_khớp, tổng_số_chuỗi_phải_khớp),
```

- Thêm mã luật vào `RULE_META`: confidence (`low` nếu phần mềm hợp pháp cũng hay dùng, xem trên) và mã ATT&CK.
  Luật thiếu trong bảng mặc định là `medium`.
- Chuỗi được so khớp **không phân biệt hoa thường**, cả dạng ASCII lẫn UTF-16 (chuỗi Windows).
- Một API "nguy hiểm" thường chỉ là **khả năng**. Muốn kết luận **hành vi**, viết luật ngữ cảnh đòi thêm bằng chứng
  bổ trợ (vd. `KEYLOG.EXFIL` = bắt phím + gửi ra ngoài). Các nhóm chuỗi dùng chung (`_KEY_CAPTURE`, `_EXFIL`,
  `_INJECT_API`…) nằm ngay trên `_INDICATORS`.
- **Đừng để một chuỗi đơn lẻ quyết định mức HIGH.** Benchmark cho thấy đây là nguồn báo nhầm chính: `pty.spawn(`
  nằm trong ví dụ của thư viện `rich`, `.onion` nằm trong thư viện mạng của Go. Hãy đòi nhiều nhóm bằng chứng
  (vd. `RANSOM.NOTE` cần cả lời đòi tiền chuộc **và** cách trả tiền).
- Tên ngắn dễ trùng (vd. tên họ mã độc): thêm mã luật vào `_WORD_START_RULES` để chỉ khớp khi là **một token**:
  trước không phải chữ/số, sau không phải chữ thường (`DcRatBuilder` khớp theo CamelCase, `dcrates` không khớp).
- Thêm test cho **cả hai chiều** vào `tests/test_detection.py`: mẫu phải bị bắt và mẫu sạch tương tự không bị bắt.

## Thêm luật YARA

Bỏ file `.yar` vào `archive_guard/data/rules/` (đi kèm repo) hoặc dùng `--yara` (riêng máy bạn). Phần `meta` quyết định điểm:

```yara
rule My_Keylogger {
    meta:
        description = "Keylogger viết bằng Python"
        severity = "high"          // low | medium | high | critical
        category = "keylogger"     // nhóm hành vi, xem CATEGORIES trong rules.py
        confidence = "medium"      // tùy chọn: low | medium | high (mặc định: high nếu critical, còn lại medium)
        attack = "T1056.001"       // tùy chọn: mã kỹ thuật MITRE ATT&CK
    strings:
        $a = "pynput.keyboard"
        $b = "smtplib"
    condition:
        all of them
}
```

Bộ luật cộng đồng nên thử: [Yara-Rules/rules](https://github.com/Yara-Rules/rules),
[Neo23x0/signature-base](https://github.com/Neo23x0/signature-base).

## Thêm mã băm

File text, mỗi dòng `mã_băm [tên_họ]` (MD5/SHA1/SHA256; dòng `#` là chú thích), rồi `--hashes file.txt`.
Mọi file `archive_guard/data/*.txt` được nạp tự động. Đổi danh sách họ tải từ MalwareBazaar: `FAMILIES` trong
`archive_guard/malwarebazaar.py` (nhóm của họ quyết định nhóm hành vi khi trùng mã băm).

## Quy trình khi sửa luật

Mọi thay đổi luật đều đổi `rules_version` và **phải đo lại** báo nhầm:

1. Chạy benchmark trên bộ phần mềm sạch **trước** khi sửa (`python -m archive_guard.benchmark --benign …`).
2. Sửa luật, thêm test hai chiều. `tests/test_confidence.py` kiểm tra bộ mẫu tổng hợp `tests/positives.py`
   không bị tụt kết luận.
3. Đo lại trên một bộ **chưa từng dùng để chỉnh luật**; ghi kết quả vào `docs/BENCHMARK.md` và `benchmark/`.

Lý do và phương pháp: [BENCHMARK.md](BENCHMARK.md).
