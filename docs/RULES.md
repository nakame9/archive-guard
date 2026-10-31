# Luật phát hiện và cách chấm điểm

## Cách chấm điểm

Mỗi phát hiện (finding) có **mức độ** và thuộc một **nhóm hành vi** (keylogger, worm, stealer…):

| Mức độ | Điểm |
|---|---|
| `LOW` | 10 |
| `MEDIUM` | 30 |
| `HIGH` | 60 |
| `CRITICAL` | 100 |

Điểm của một file = tổng mức **nặng nhất của từng nhóm** (tối đa 100). Nhiều bằng chứng cho **cùng** một hành vi
không cộng dồn; nhiều hành vi **khác** nhau (vd. ghi phím + gửi dữ liệu ra ngoài + tự khởi động) thì cộng lại.

| Điểm | Kết luận |
|---|---|
| < 30 | SẠCH |
| 30 – 79 | ĐÁNG NGỜ |
| ≥ 80, hoặc có phát hiện CRITICAL (trùng mã băm, ClamAV, YARA critical) | NGUY HIỂM |

Không có dấu hiệu nhưng có phần chưa kiểm tra được → `CHƯA QUÉT ĐỦ` (xem [USAGE.md](USAGE.md#kết-luận-và-mã-thoát)).
Kết luận của cả file nén là kết luận nặng nhất trong các file bên trong. Code: `score_and_verdict()` trong
`archive_guard/scanner.py`.

## Các lớp phát hiện

| Lớp | Phát hiện | Code |
|---|---|---|
| Tên file | đuôi kép `hoadon.pdf.exe`, ký tự đảo chiều Unicode, chèn khoảng trắng giấu đuôi, `.scr/.hta/.lnk/.iso…`, `autorun.inf`, Zip Slip, symlink nguy hiểm | `check_name()` |
| Nội dung | `.exe` đội lốt `.pdf/.jpg`, macro VBA, định dạng chứa file chưa hỗ trợ | `check_content()`, `file_kind()` |
| Packer | tên section UPX/ASPack/Themida/VMProtect/MPRESS/NsPack/Enigma/PECompact…, dấu `UPX!`, entropy > 7.2 ở vùng mã | `check_packer()` |
| Hành vi | 21 nhóm chỉ dấu, chuỗi ASCII + UTF-16, quét **trọn** file theo khúc 8 MB | `_INDICATORS` |
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

- Chuỗi được so khớp **không phân biệt hoa thường**, cả dạng ASCII lẫn UTF-16 (chuỗi Windows).
- **Đừng để một chuỗi đơn lẻ quyết định mức HIGH.** Benchmark cho thấy đây là nguồn báo nhầm chính: `pty.spawn(`
  nằm trong ví dụ của thư viện `rich`, `.onion` nằm trong thư viện mạng của Go. Hãy đòi nhiều nhóm bằng chứng
  (vd. `RANSOM.NOTE` cần cả lời đòi tiền chuộc **và** cách trả tiền).
- Tên ngắn dễ trùng (vd. tên họ mã độc): thêm mã luật vào `_WORD_START_RULES` để chỉ khớp khi đứng **đầu một từ**.
- Thêm test cho **cả hai chiều** vào `tests/test_detection.py`: mẫu phải bị bắt và mẫu sạch tương tự không bị bắt.

## Thêm luật YARA

Bỏ file `.yar` vào `archive_guard/data/rules/` (đi kèm repo) hoặc dùng `--yara` (riêng máy bạn). Phần `meta` quyết định điểm:

```yara
rule My_Keylogger {
    meta:
        description = "Keylogger viết bằng Python"
        severity = "high"          // low | medium | high | critical
        category = "keylogger"     // nhóm hành vi, xem CATEGORIES trong rules.py
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
2. Sửa luật, thêm test hai chiều.
3. Đo lại trên một bộ **chưa từng dùng để chỉnh luật**; ghi kết quả vào `docs/BENCHMARK.md` và `benchmark/`.

Lý do và phương pháp: [BENCHMARK.md](BENCHMARK.md).
