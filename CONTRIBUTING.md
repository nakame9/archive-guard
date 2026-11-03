# Đóng góp cho ArchiveGuard

Cảm ơn bạn! Chọn đúng kênh trước:

| Bạn muốn | Làm gì |
|---|---|
| Báo file sạch bị gắn cờ / mã độc bị bỏ sót | Mẫu issue [**Báo nhầm** / **Bỏ sót**](https://github.com/nakame9/archive-guard/issues/new/choose) – chỉ SHA-256 + nguồn công khai, **không gửi mã độc** |
| Báo lỗi chương trình | Mẫu issue **Lỗi** |
| Báo lỗ hổng bảo mật | Báo riêng theo [SECURITY.md](SECURITY.md) |
| Sửa code, viết luật, sửa tài liệu | Đọc tiếp |

## Chuẩn bị

```bash
git clone https://github.com/nakame9/archive-guard.git && cd archive-guard
pip install --require-hashes -r requirements-dev.txt   # đúng phiên bản CI dùng, kiểm tra hash từng gói
pip install --no-deps -e .
pytest -q          # toàn bộ test (~30 giây)
ruff check .       # lint
```

Trước khi sửa code, đọc [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) – có bảng "muốn sửa X thì sửa ở đâu".
CI chạy test trên Linux (x86_64, arm64), Windows, macOS với Python 3.10 và 3.13, cộng lint, pip-audit và Docker;
PR chỉ được gộp khi CI xanh.

## Quy tắc bắt buộc

1. **Không đưa mã độc thật vào repo, issue hay PR**, kể cả dạng nén có mật khẩu. Mẫu thử được tạo trong bộ nhớ
   (`tests/helpers.py`, nội dung vô hại, địa chỉ `.invalid`); mẫu thật chỉ nhắc bằng SHA-256.
2. **Không biến lỗi thành SẠCH.** Phần không kiểm tra được phải dẫn tới `CHƯA QUÉT ĐỦ` hoặc lỗi.
3. **Thay đổi hành vi phải có test**; sửa lỗi thì kèm một test thất bại trên code cũ.
4. **JSON chỉ được thêm trường.** Đổi tên/xóa/đổi nghĩa phải tăng `SCHEMA_VERSION` (`cli.py`) và sửa `SCHEMA_V1`
   (`tests/test_cli.py`).
5. **Dependency:** ưu tiên thư viện chuẩn; đổi `pyproject.toml` thì tạo lại lock file
   ([cách làm](docs/MAINTAINING.md#cập-nhật-dependency)) – CI kiểm tra lock khớp.
6. **Thành phần bên thứ ba** (luật YARA, dữ liệu, file mẫu) chỉ nhận khi giấy phép cho phép phân phối lại trong repo
   MIT (không GPL, không CC BY-NC); ghi vào [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
7. Ghi thay đổi vào mục `[Chưa phát hành]` của [CHANGELOG.md](CHANGELOG.md).

## Viết luật phát hiện

Đọc [docs/RULES.md](docs/RULES.md) (cách chấm điểm, `RULE_META`, luật ngữ cảnh). Tóm tắt:

1. **Bắt đầu từ dữ liệu:** một issue "Bỏ sót" hoặc một kỹ thuật MITRE ATT&CK cụ thể (ghi mã vào `RULE_META`).
2. **Chọn đúng chỗ:** chuỗi/API → `_INDICATORS` (`rules.py`); cấu trúc định dạng (LNK, OLE, ZIP…) → hàm `check_*`
   riêng; chữ ký một họ mã độc → file YARA trong `archive_guard/data/rules/`.
3. **Khả năng hay hành vi?** API mà phần mềm hợp pháp cũng dùng là *khả năng* (`confidence: low`). Muốn kết luận
   *hành vi*, đòi thêm bằng chứng bổ trợ trong cùng file – đừng nâng mức độ của một chuỗi đơn lẻ.
4. **Test hai chiều** (`tests/test_detection.py`): mẫu xấu bị bắt **và** mẫu sạch giống nhất có thể không bị bắt.
5. Kiểu tấn công mới → thêm một mẫu vào `tests/positives.py` để các thay đổi sau không làm tụt kết luận của nó.

## Đo báo nhầm trước khi gửi PR đổi luật

Mọi PR đổi luật (kể cả YARA) phải đo **trước và sau** trên các bộ phần mềm sạch đã công bố:

```bash
python benchmark/tai_bo_sach.py benchmark/benign-corpus.txt    sach/bo1       # tải lại, kiểm tra SHA-256
python benchmark/tai_bo_sach.py benchmark/holdout-corpus-1.txt sach/kiemtra1  # (~1,4 GB cho cả ba bộ)
python benchmark/tai_bo_sach.py benchmark/holdout-corpus-2.txt sach/kiemtra2
python benchmark/dung_mau_tong_hop.py tonghop/                                # mẫu dương tính tổng hợp

git stash && python -m archive_guard.benchmark --malicious tonghop --benign sach/bo1 --no-clamav --out truoc && git stash pop
python -m archive_guard.benchmark --malicious tonghop --benign sach/bo1 --no-clamav --out sau
```

Lặp lại với `kiemtra1`, `kiemtra2`, rồi dán bảng "theo nhóm" và danh sách ca báo nhầm của `truoc.md`/`sau.md` vào PR.

### Tiêu chí review luật

| Câu hỏi | Chặn merge nếu |
|---|---|
| Báo nhầm trên 3 bộ sạch | Có gói **mới** bị ĐÁNG NGỜ/NGUY HIỂM mà PR không giải thích và được chấp nhận rõ ràng |
| NGUY HIỂM | Có thêm bất kỳ gói sạch nào bị NGUY HIỂM |
| Kỷ luật dữ liệu | Luật được chỉnh cho hết báo nhầm trên **bộ kiểm tra 3** (`holdout-corpus-2.txt`) – bộ đó chỉ để đo |
| Mẫu tổng hợp | Mẫu nào trong `tests/positives.py` bị tụt kết luận |
| Chuỗi đơn lẻ quyết định mức HIGH | Không có bằng chứng bổ trợ hoặc lý do rõ ràng |
| Test hai chiều, `RULE_META`, CHANGELOG | Thiếu |
| Luật lấy từ nơi khác | Giấy phép không tương thích, hoặc thiếu nguồn/tác giả |

## Gửi PR

Mẫu PR có sẵn checklist. Giữ PR nhỏ, một chủ đề; mô tả **vì sao** thay đổi. Người giữ repo review theo các mục trên;
việc phát hành do người giữ repo làm ([docs/MAINTAINING.md](docs/MAINTAINING.md)).
