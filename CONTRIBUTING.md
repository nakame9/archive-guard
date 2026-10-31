# Đóng góp

Cảm ơn bạn muốn góp sức. Trước khi sửa code, đọc [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): có bảng
"muốn sửa X thì sửa ở đâu".

## Chuẩn bị

```bash
git clone https://github.com/nakame9/archive-guard.git
cd archive-guard
pip install -e ".[yara,dev]"
pytest -q          # chạy toàn bộ test (~15 giây)
ruff check .       # lint: chỉ bắt lỗi thật (tên chưa định nghĩa, import thừa…)
```

CI chạy test trên Linux, Windows và macOS với Python 3.10 và 3.13, cộng lint. PR chỉ được gộp khi CI xanh.

## Quy tắc

1. **Không bao giờ đưa mã độc thật vào repo, issue hay PR**, kể cả dạng nén có mật khẩu. Mẫu thử được tạo trong
   bộ nhớ lúc chạy test (`tests/helpers.py`); khi cần nói về một mẫu thật, dùng mã SHA-256.
2. **Không được biến lỗi thành SẠCH.** Phần không kiểm tra được phải dẫn tới `CHƯA QUÉT ĐỦ` hoặc lỗi.
3. **Thay đổi hành vi phải có test** ở đúng file trong `tests/` (bảng ở cuối ARCHITECTURE.md). Sửa lỗi thì thêm một
   test thất bại trên code cũ.
4. **Sửa luật phát hiện phải đo lại báo nhầm** theo quy trình trong [docs/RULES.md](docs/RULES.md#quy-trình-khi-sửa-luật).
   Mỗi luật mới cần test hai chiều: mẫu xấu bị bắt, mẫu sạch tương tự không bị bắt.
5. **JSON chỉ được thêm trường.** Đổi tên, xóa hay đổi nghĩa một trường phải tăng `SCHEMA_VERSION` trong `cli.py`
   và cập nhật `SCHEMA_V1` trong `tests/test_cli.py`.
6. **Không thêm dependency bắt buộc** nếu thư viện chuẩn làm được; thành phần nâng cao để ở `optional-dependencies`.
7. Ghi thay đổi vào mục `[Chưa phát hành]` của [CHANGELOG.md](CHANGELOG.md).

## Phát hành

1. Chuyển mục `[Chưa phát hành]` trong CHANGELOG thành số phiên bản mới kèm ngày.
2. Tăng `version` trong `pyproject.toml` và `__version__` trong `archive_guard/__init__.py`.
3. Commit, đợi CI xanh, rồi gắn tag: `git tag v0.11.0 && git push --tags`.

## Báo nhầm / bỏ sót

Mở issue bằng mẫu **"Báo nhầm / bỏ sót"**: ghi mã SHA-256 của file, kết luận nhận được, kết luận mong đợi, và phần
báo cáo JSON liên quan. Với phần mềm sạch, kèm tên gói và phiên bản để người khác tải lại được.
