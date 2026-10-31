## Thay đổi gì, vì sao


## Kiểm tra

- [ ] `pytest -q` và `ruff check .` đều qua
- [ ] Có test cho hành vi mới / test thất bại trên code cũ nếu là sửa lỗi
- [ ] Phần không kiểm tra được vẫn dẫn tới `CHƯA QUÉT ĐỦ` hoặc lỗi, không bao giờ là SẠCH
- [ ] Sửa luật phát hiện: đã đo lại báo nhầm theo [docs/RULES.md](https://github.com/nakame9/archive-guard/blob/main/docs/RULES.md#quy-trình-khi-sửa-luật) và ghi kết quả
- [ ] JSON chỉ thêm trường (nếu đổi/xóa trường: đã tăng `SCHEMA_VERSION`)
- [ ] Đã ghi vào mục `[Chưa phát hành]` của `CHANGELOG.md`
- [ ] Không có mã độc thật trong PR
