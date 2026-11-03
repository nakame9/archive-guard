# Thành phần của bên thứ ba

Mã nguồn ArchiveGuard dùng giấy phép [MIT](LICENSE). Các thành phần dưới đây **nằm trong repo** nhưng thuộc giấy
phép hoặc điều khoản riêng của chủ sở hữu; giấy phép MIT không áp dụng cho chúng.

| Thành phần | Vị trí | Nguồn | Giấy phép / điều khoản |
|---|---|---|---|
| Luật YARA (140 file `crime_*`, `mal_*`) | `archive_guard/data/rules/signature-base/` | [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) – Florian Roth và cộng sự | [Detection Rule License 1.1](archive_guard/data/rules/signature-base/LICENSE); một số luật ghi CC BY 4.0 trong `meta`. Không sửa nội dung; tên tác giả luật được in khi luật khớp (yêu cầu của DRL). Chi tiết: [README của thư mục](archive_guard/data/rules/signature-base/README.md) |
| Danh sách mã băm mã độc | `archive_guard/data/malwarebazaar.txt`, GitHub Release `hash-db` | [MalwareBazaar](https://bazaar.abuse.ch/), [URLhaus](https://urlhaus.abuse.ch/) – abuse.ch | Điều khoản sử dụng của abuse.ch: miễn phí theo nguyên tắc *fair use*; dùng cho mục đích thương mại có thể cần gói trả phí của abuse.ch. Kiểm tra điều khoản hiện hành trước khi dùng thương mại |
| File RAR mẫu cho test | `tests/data/rar5-solid.rar`, `tests/data/rar5-psw.rar` | [markokr/rarfile](https://github.com/markokr/rarfile) – Marko Kreen | ISC. Chi tiết: [tests/data/README.md](tests/data/README.md) |

**Không đi kèm repo** (được cài riêng, mỗi gói theo giấy phép của nó):

- Thư viện Python (py7zr, rarfile, yara-python, sigstore…): danh sách đầy đủ, kèm phiên bản và giấy phép, có trong
  SBOM CycloneDX của mỗi bản phát hành.
- `unrar` (giấy phép freeware của RARLAB, gói `non-free` của Debian) được cài vào image Docker khi **bạn** build
  image; repo không phân phối file nhị phân này.
- ClamAV, 7-Zip: do người dùng tự cài.

Thêm thành phần bên thứ ba mới: ghi vào bảng trên, giữ nguyên file giấy phép gốc, và chỉ chọn giấy phép cho phép
phân phối lại trong repo MIT (không GPL, không CC BY-NC) – xem CONTRIBUTING.md.
