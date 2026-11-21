# Kế hoạch phát triển ArchiveGuard (2026-11-23 → 2027-01-17)

Kế hoạch chung giữa Claude và Codex sau 3 lượt thảo luận mỗi bên, ngày 2026-11-21. Dựa trên mã nguồn `main` @ `d568291`
và trạng thái GitHub tại thời điểm đó. Thời gian là ước lượng cho một người giữ repo. Đây là đề xuất; nếu được duyệt
thì gộp vào `docs/ROADMAP.md`.

## 1. Hiện trạng (đã kiểm chứng)

| Mục | Trạng thái | Nguồn |
|---|---|---|
| CI `tests` | **Đỏ mọi lần chạy từ 2026-11-14.** Chỉ job `audit` lỗi: `dnspython 2.9.1` dính CVE-2026-128089 (bản sửa 2.9.2), pin trong `requirements-dev.txt`. Toàn bộ ma trận test (Linux/macOS/Windows/ARM, Py 3.10/3.13) xanh | `gh run view 44697139400` |
| PR Dependabot | 7 PR mở (#3, #4, #8–#12), đều đỏ vì cùng lý do | `gh pr list` |
| Phát hành | Không có tag nào ngoài `hash-db`; tag `v0.17.1` mà docs trỏ tới **không tồn tại**; chưa lên PyPI. M1 + M3 nằm trên `main`, chưa phát hành | `git tag`, `gh release list` |
| Recall trên mã độc thật | Chưa đo | README, ROADMAP |
| Đóng băng tính năng | Từ 2026-11-08, 6 tuần (đến khoảng 2026-12-20) hoặc tới khi xong M2 | docs/ROADMAP.md |

Chất lượng code nhìn chung tốt: bất biến "chưa quét đủ thì không SẠCH" được thiết kế rõ, ngân sách tài nguyên dùng chung
cho mọi tầng, worker không được tin cậy, `BudgetExceeded` kế thừa `BaseException` nên không bị nuốt. Test chưa chạy được
trên máy này (bị từ chối quyền), nên kết luận test xanh lấy từ CI.

## 2. Lỗi và rủi ro tìm thấy (đã đối chiếu với code)

| # | Vấn đề | Vị trí | Mức |
|---|---|---|---|
| 1 | File luật YARA biên dịch lỗi bị bỏ qua, chỉ ghi vào chuỗi trạng thái, **không** vào `incomplete_reasons`. Luật đi kèm bị hỏng thì độ phủ âm thầm giảm mà vẫn ra SẠCH | `engines.py:30-40` | Cao |
| 2 | `check_report` không kiểm tra kết luận tổng ≥ kết luận nặng nhất của từng file, cũng không kiểm tra `complete` khớp với `incomplete`. `disposition` của API đi theo kết luận tổng | `isolate.py:163-177` | Cao |
| 3 | `isolate.scan` chỉ giữ `reports[0]` và `sandbox`, bỏ mất `engines`, `rules_version`, `rules_components`, nên kết quả `scan_file()` không cho biết engine nào thực sự đã chạy | `isolate.py:221-228` | Trung bình |
| 4 | Process cha đọc stdout/stderr/report của worker (bên không tin cậy) mà không giới hạn kích thước | `isolate.py:72, 220` | Trung bình |
| 5 | `release.yml` chạy build → sign → pypi mà không phụ thuộc vào test/audit | `release.yml:55,89,106` | Cao (chuỗi cung ứng) |
| 6 | THREAT_MODEL ghi ClamAV là bước bắt buộc, nhưng code coi "chưa cài" là tắt (ra SẠCH). Docs và code mâu thuẫn | `THREAT_MODEL.md:9,144`, `scanner.py:242` | Docs |
| 7 | `malwarebazaar.update()` gộp vào file đang có trong repo. Nếu ngừng commit (mục tiêu M4) mà không lấy dữ liệu gốc từ Release `hash-db` thì sẽ mất lịch sử mã băm | `malwarebazaar.py:131` | Cao (khi làm M4) |
| 8 | Entry ZIP bị giấu chỉ được báo (tối đa 20), nội dung không được quét. Danh mục 7z/RAR được nạp toàn bộ trước khi ngân sách kịp chặn (đã ghi `shortcut`) | `extract.py:752`, `extract.py:898` | Đã biết |

## 3. Lộ trình

### Giai đoạn A: 0.18.0 "nền đáng tin" (tuần 1–2, 23/11 → 06/12)

1. Nâng `dnspython` lên 2.9.2 và tạo lại hash bằng `uv pip compile`, giữ nguyên `pip-audit --strict`. Rebase và cho chạy lại các PR Dependabot.
2. YARA: thiếu `yara-python` thì coi là tắt. Bộ luật đã chọn (đi kèm hoặc `--yara`) có file lỗi biên dịch, kể cả khi chỉ lỗi một phần, thì ra CHƯA QUÉT ĐỦ với mã mới `RULES_UNAVAILABLE` (chỉ thêm mã mới).
3. `check_report`: từ chối báo cáo tự mâu thuẫn (SẠCH đứng trên file con nguy hiểm, `complete`/`incomplete` lệch nhau, thiếu trường bắt buộc), kết quả là `WORKER_ERROR`.
4. Đưa `engines`, `rules_version`, `rules_components` thực tế vào kết quả `scan_file()` (chỉ thêm trường).
5. Giới hạn số byte đọc stdout/stderr/report của worker ở N+1 byte; vượt thì ra `WORKER_ERROR`. Ghi rõ trong docs rằng dung lượng đĩa tạm của worker là giới hạn riêng, **chưa** được giải quyết.
6. Sửa docs về ClamAV: "đã cài nhưng lỗi" thì CHƯA QUÉT ĐỦ, "chưa cài" thì tắt và hiện trong `engines`.
7. `release.yml`: chạy test + audit **trên đúng commit được tag** trước khi build; tag lệch với phiên bản trong `pyproject.toml` thì chặn; smoke test wheel/sdist trong môi trường sạch (CLI, API, nạp luật đi kèm).
8. Người giữ repo: bật Private vulnerability reporting, cấu hình PyPI Trusted Publisher, ký tag `v0.18.0`, sửa các ví dụ đang trỏ tới `v0.17.1`.

**Xong khi:** CI xanh toàn bộ; 0.18.0 có trên PyPI kèm attestation; các test hồi quy sau đều có (mỗi dòng mở rộng một test hiện có):
- ClamAV/YARA không cài thì trạng thái là tắt; ClamAV đã cài nhưng lỗi thì CHƯA QUÉT ĐỦ; tắt bằng cờ vẫn hoạt động.
- File YARA hỏng (đi kèm hoặc `--yara`, kể cả biên dịch được một phần) ra `RULES_UNAVAILABLE`, các luật còn lại vẫn phát hiện được.
- Báo cáo worker mâu thuẫn hoặc sai cấu trúc ra `WORKER_ERROR`.
- API giữ được trạng thái engine thực tế và `rules_version`, kể cả trên đường ClamAV chạy ở process cha.
- Đọc output worker: đúng N byte thì chấp nhận, N+1 byte thì từ chối trước khi parse và không bao giờ ra SẠCH.
- Test/audit lỗi trên commit được tag, hoặc tag lệch phiên bản, thì chặn phát hành.

### Giai đoạn B: 0.19.0 = M2a "độ phủ byte ZIP, ghi nhận trước" (tuần 3–5, 07/12 → 27/12)

- **Độ phủ cấu trúc** = hợp các vùng đã kiểm tra hợp lệ / độ dài file, công bố riêng các khoảng chưa giải thích được. Tách bạch với "đã kiểm tra nội dung". Các vùng được coi là đã giải thích (theo PKWARE APPNOTE):
  1. Local header: các trường cố định, tên file, extra field đã khai báo (gồm padding căn lề và ZIP64).
  2. Dữ liệu entry: phần đã nén hoặc stored, cộng khung mã hóa. Byte đã mã hóa mà không giải mã được thì vẫn tính là chưa kiểm tra nội dung.
  3. Data descriptor đứng ngay sau entry: dạng 12/16 byte hoặc 20/24 byte (ZIP64), có hoặc không có chữ ký, khớp kích thước và CRC.
  4. Central directory, các bản ghi ZIP64 EOCD/locator, EOCD và comment, đã kiểm tra vị trí, độ dài, số lượng và offset.
  6. Vỏ SFX được nhận diện, quét như file thực thi bên ngoài và tính offset tường minh. Byte bất kỳ đứng trước **không** được miễn chung.
  - (5) APK signing block: hoãn, chỉ làm nếu bộ phần mềm sạch cho thấy APK/JAR bị báo nhầm là "chưa giải thích được".
- Giai đoạn này **chỉ ghi nhận** trong trường `coverage`, chưa đổi kết luận. Công bố tỷ lệ "còn vùng chưa giải thích" trên 3 bộ phần mềm sạch hiện có.
- Quét nội dung entry bị giấu chỉ khi local header có kích thước khai báo (không dùng data descriptor) và phương thức nén được hỗ trợ. Việc quét dùng chung ngân sách và kiểm CRC, vẫn giữ `ARCHIVE.HIDDEN_ENTRY`. Trường hợp khác thì CHƯA QUÉT ĐỦ.
- Evasion corpus: khoảng 15–25 mẫu do script trong `tests/` sinh ra (không commit blob nhị phân), mỗi mẫu có kết luận mong đợi.
- So sánh với 7-Zip (pin phiên bản): đối chiếu danh sách `7z l -slt` với `zipfile` trên evasion corpus, kèm hash nội dung giải nén (có giới hạn) cho các mẫu mơ hồ về offset hoặc trùng tên.
- Một target atheris cho `zip_anomalies`/`_zip`, chạy trong CI có giới hạn thời gian. Hoãn ClusterFuzzLite.

**Xong khi:** mọi mẫu evasion có kết quả mong đợi và **không mẫu nào ra SẠCH**; tỷ lệ vùng chưa giải thích trên bộ sạch đã được công bố.

### Giai đoạn C: M4 "lưu mã băm không cần commit" (tuần 6, 28/12 → 03/01)

- Workflow lấy dữ liệu gốc từ Release `hash-db` đã xác minh chữ ký, rồi mới gộp mã mới vào; các lượt chạy nối tiếp nhau (concurrency group); lỗi tải hoặc lỗi chữ ký thì giữ nguyên trạng thái cũ. Chỉ bỏ bước commit vào `main` sau khi những điều này đã chạy ổn.

**Xong khi:** hai lượt cập nhật liên tiếp giữ được các mã chưa hết hạn, lượt lỗi không làm mất dữ liệu, và `main` không đổi.

### Giai đoạn D: M2b "bắt buộc" (tuần 7–8, 04/01 → 17/01)

- Bật quy tắc: khoảng chưa giải thích được thì ≥ CHƯA QUÉT ĐỦ, quyền sở hữu hoặc offset mâu thuẫn thì ≥ ĐÁNG NGỜ. Tỷ lệ trên bộ sạch chỉ dùng để quyết định cần hỗ trợ thêm cấu trúc nào và triển khai theo thứ tự nào. Nó **không** phải lý do để bỏ qua byte chưa giải thích. Cấu trúc chưa hỗ trợ (kể cả APK signing block nếu chưa làm) thì CHƯA QUÉT ĐỦ.
- M2 chỉ được coi là xong khi quy tắc này đã có trong một bản phát hành.

### Song song: đo recall (người giữ repo, trong máy ảo)

- Chốt danh sách mẫu mã độc (đã loại trùng) và một bộ holdout riêng **trước** mọi lần chỉnh luật. Tách các trường hợp: khớp mã băm, phát hiện bằng lớp khác, chưa quét đủ, và bỏ sót. Công bố mẫu số, thành phần họ mã độc, phiên bản engine/CSDL. Không tuyên bố recall cho toàn bộ quần thể mã độc.
- **Mốc kiểm tra: 2026-12-20**, cùng ngày xem lại đợt đóng băng tính năng. Số liệu recall quyết định thứ tự backlog (PDF, ISO/OneNote, YARA cho AgentTesla/Formbook/Lumma…).

## 4. Đã thống nhất, đã thay đổi, đã hoãn

**Thống nhất:** ưu tiên chứng minh những gì đã tuyên bố hơn là thêm tính năng; phát hành sớm; M2 chia hai bước, ghi nhận rồi mới bắt buộc; định nghĩa độ phủ cấu trúc ở trên.

**Thay đổi so với đề xuất ban đầu:**
- Codex: phát hành ở tuần 6–8. Đổi thành 0.18.0 ở tuần 1–2 theo đề xuất của Claude, vì M1/M3 đang nằm trên `main` mà không ai cài được, và docs đang trỏ tới một tag không tồn tại.
- Codex: coi việc thiếu ClamAV là lỗi bất biến. Đổi thành chỉ sửa docs, vì README định vị ClamAV là tùy chọn, và nếu ra mã 4 khi chưa cài thì mọi bản cài mặc định đều mất tác dụng. Codex đồng ý, và thêm quy tắc tương tự cho YARA.
- Claude: đo recall nằm ngoài lộ trình. Đổi thành một nhánh song song có mốc kiểm tra cố định, theo góp ý của Codex.
- Claude: so sánh với 7-Zip chỉ bằng danh sách file. Codex bổ sung hash nội dung cho các mẫu mơ hồ, vì so danh sách không so được byte.
- Claude: tính SFX bằng `has_trailing_zip`. Codex chỉ ra hàm này chỉ nhận diện ZIP ở cuối, không giải thích được byte đứng trước, nên phải tính vỏ SFX tường minh.
- Claude: giới hạn đọc output worker. Codex lưu ý giới hạn này chỉ bảo vệ RAM của process cha, không bảo vệ đĩa tạm. Hai việc được tách riêng.

**Hoãn:** ClusterFuzzLite, `--require-clamav`, APK signing block (có điều kiện), định dạng mới (PDF, ISO, OneNote), gói YARA mới, README tiếng Anh, sandbox Windows gốc, image GHCR + cosign, seccomp aarch64, sdist tái lập từng bit, giới hạn dung lượng đĩa tạm của worker (chỉ ghi vào docs).

## 5. Rủi ro của kế hoạch

1. **Tự tin sai:** độ phủ cấu trúc, việc đã kiểm tra nội dung, và việc phát hiện được mã độc là ba tuyên bố khác nhau. Phủ 100% byte, hay hai parser cho cùng kết quả, đều không chứng minh file an toàn.
2. **Sức một người:** phát hành, sửa lỗi bảo mật, M2 và đo recall tranh nhau thời gian. Nếu thiếu thời gian thì thu hẹp M2, không lùi 0.18.
3. **Mất lịch sử mã băm** khi bỏ bước commit (xem giai đoạn C).
