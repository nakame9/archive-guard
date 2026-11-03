# Luật YARA từ signature-base

- Nguồn: https://github.com/Neo23x0/signature-base (thư mục `yara/`), commit `36ab70428fc5b52701b7ee6107c853ff019ed759`
  (2026-10-29). Tác giả chính: Florian Roth và các cộng tác viên; tác giả từng luật ghi trong trường `author`.
- Giấy phép: **Detection Rule License (DRL) 1.1**, toàn văn trong file `LICENSE` bên cạnh. Một số luật ghi giấy phép
  riêng **CC BY 4.0** trong `meta` (vẫn giữ nguyên).
- Không sửa nội dung luật. Theo DRL, khi một luật khớp, ArchiveGuard in kèm tên tác giả luật (`engines.yara_scan`).

## Đã chọn gì

Mọi file `crime_*.yar` và `mal_*.yar` (mã độc phổ thông, không phải APT/công cụ tấn công/khai thác lỗ hổng), trừ:

| File | Lý do bỏ |
|---|---|
| `crime_nansh0u.yar` | Giấy phép CC BY-NC 4.0 (cấm dùng thương mại) – không tương thích với MIT |
| `mal_qbot_feb23.yar` | Luật lấy từ CAPEv2 (GPL-3.0) |

Không lấy `gen_*`/`hktl_*`: luật chung và luật công cụ tấn công dễ báo nhầm ở công cụ hai mặt (impacket, mimikatz…).

## Mức độ

Luật signature-base không có `severity`/`category`; ArchiveGuard suy từ `score`: ≥ 80 → CRITICAL (kết luận NGUY HIỂM),
60–79 → HIGH, < 60 → MEDIUM; nhóm hiển thị là "Mã độc đã biết". Báo nhầm đo được: xem docs/BENCHMARK.md, vòng 4.

## Cập nhật

Sửa cả file `VERSION` (in trong dòng trạng thái và trường `engines.yara` của báo cáo JSON).
Chép lại các file từ bản mới của signature-base, giữ danh sách loại trừ ở trên, kiểm tra trường `license` của các
luật mới, rồi đo lại báo nhầm trên các bộ phần mềm sạch trước khi commit.
