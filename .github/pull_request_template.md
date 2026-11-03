## Thay đổi gì, vì sao


## Kiểm tra

- [ ] `pytest -q` và `ruff check .` đều qua
- [ ] Có test cho hành vi mới / test thất bại trên code cũ nếu là sửa lỗi
- [ ] Phần không kiểm tra được vẫn dẫn tới `CHƯA QUÉT ĐỦ` hoặc lỗi, không bao giờ là SẠCH
- [ ] Sửa luật phát hiện (kể cả YARA): đã đo báo nhầm **trước và sau** trên 3 bộ sạch + bộ mẫu tổng hợp theo
      [CONTRIBUTING.md](https://github.com/nakame9/archive-guard/blob/main/CONTRIBUTING.md#đo-báo-nhầm-trước-khi-gửi-pr-đổi-luật)
      và dán kết quả; không chỉnh luật dựa trên bộ kiểm tra 3
- [ ] Luật mới có test hai chiều, `RULE_META` (confidence + mã ATT&CK); luật YARA lấy từ nơi khác có giấy phép tương thích
- [ ] JSON chỉ thêm trường (nếu đổi/xóa trường: đã tăng `SCHEMA_VERSION`)
- [ ] Đã ghi vào mục `[Chưa phát hành]` của `CHANGELOG.md`
- [ ] Không có mã độc thật trong PR
