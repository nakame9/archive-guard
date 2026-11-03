# Đóng góp

Cảm ơn bạn muốn góp sức. Trước khi sửa code, đọc [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): có bảng
"muốn sửa X thì sửa ở đâu".

## Chuẩn bị

```bash
git clone https://github.com/nakame9/archive-guard.git
cd archive-guard
pip install --require-hashes -r requirements-dev.txt   # đúng phiên bản CI dùng, kiểm tra hash từng gói
pip install --no-deps -e .
pytest -q          # chạy toàn bộ test (~15 giây)
ruff check .       # lint: chỉ bắt lỗi thật (tên chưa định nghĩa, import thừa…)
```

CI chạy test trên Linux (x86_64, arm64), Windows và macOS với Python 3.10 và 3.13, cộng lint, pip-audit, Docker.
PR chỉ được gộp khi CI xanh.

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
   Đổi dependency trong `pyproject.toml` thì tạo lại lock file bằng `uv` đã pin (job `audit` của CI kiểm tra):

   ```bash
   pip install --require-hashes -r .github/requirements-tools.txt
   uv pip compile pyproject.toml --extra yara --universal --python-version 3.10 --generate-hashes -o requirements.txt
   uv pip compile pyproject.toml --extra yara --extra update --extra dev --universal --python-version 3.10 --generate-hashes -o requirements-dev.txt
   ```
7. Ghi thay đổi vào mục `[Chưa phát hành]` của [CHANGELOG.md](CHANGELOG.md).

## Phát hành

1. Chuyển mục `[Chưa phát hành]` trong CHANGELOG thành số phiên bản mới kèm ngày.
2. Tăng `version` trong `pyproject.toml` và `__version__` trong `archive_guard/__init__.py`.
3. Commit, đợi CI xanh, rồi gắn **tag có chữ ký**: `git tag -s v1.2.3 -m v1.2.3 && git push origin v1.2.3`.
4. Workflow `release` tự làm phần còn lại: build, SBOM, provenance + chữ ký Sigstore, PyPI, GitHub Release.
   Tag không khớp `version` trong `pyproject.toml` thì dừng ngay. Chạy thử (không phát hành):
   Actions → release → Run workflow.

**Thiết lập một lần** (người giữ repo):

- Ký tag bằng khóa SSH: `git config --global gpg.format ssh`,
  `git config --global user.signingkey ~/.ssh/id_ed25519.pub`, rồi thêm khóa đó vào GitHub dưới dạng
  **Signing key** (Settings → SSH and GPG keys) để tag hiện "Verified". Có thể bắt buộc bằng ruleset
  (Settings → Rules → Rulesets → nhắm vào tag → Require signed commits).
- PyPI Trusted Publishing: trên pypi.org → Account settings → Publishing → *Add a new pending publisher*:
  project `archive-guard`, owner `nakame9`, repository `archive-guard`, workflow `release.yml`, environment `pypi`.
  Không cần token PyPI nào trong repo.
- GitHub → Settings → Environments → tạo môi trường `pypi` (nên bật *Required reviewers* để mỗi lần đăng PyPI phải
  có người duyệt).

## Viết luật phát hiện mới

Đọc [docs/RULES.md](docs/RULES.md) trước (cách chấm điểm, `RULE_META`, luật ngữ cảnh). Tóm tắt:

1. **Bắt đầu từ dữ liệu:** một issue "Bỏ sót" (mẫu thật, có SHA-256) hoặc một kỹ thuật MITRE ATT&CK cụ thể. Ghi
   mã kỹ thuật vào `RULE_META`.
2. **Chọn đúng chỗ:** chuỗi/API → `_INDICATORS` trong `rules.py`; cấu trúc định dạng (LNK, OLE, ZIP…) → hàm
   `check_*` riêng; chữ ký một họ mã độc cụ thể → file YARA trong `archive_guard/data/rules/`.
3. **Khả năng hay hành vi?** API mà phần mềm hợp pháp cũng dùng là *khả năng* (`confidence: low`, một mình không gắn
   cờ). Muốn kết luận *hành vi*, đòi thêm bằng chứng bổ trợ trong cùng file (luật ngữ cảnh), đừng nâng mức độ của
   một chuỗi đơn lẻ.
4. **Test hai chiều** trong `tests/test_detection.py`: mẫu xấu bị bắt **và** mẫu sạch giống nhất có thể không bị bắt
   (vd. macro tự chạy nhưng vô hại; shortcut bình thường). Mẫu tạo trong bộ nhớ, nội dung vô hại, địa chỉ `.invalid`.
5. Thêm một mẫu vào `tests/positives.py` nếu luật bắt một kiểu tấn công mới: `test_confidence.py` giữ cho các luật
   sau này không làm tụt kết luận của nó.

## Đo báo nhầm trước khi merge

Mọi PR đổi luật (kể cả file YARA) phải đo trên **các bộ phần mềm sạch đã công bố**, trước và sau thay đổi:

```bash
# tải lại đúng các gói (SHA-256 được kiểm tra từng file; ~1,4 GB cho cả ba bộ)
python benchmark/tai_bo_sach.py benchmark/benign-corpus.txt     sach/bo1
python benchmark/tai_bo_sach.py benchmark/holdout-corpus-1.txt  sach/kiemtra1
python benchmark/tai_bo_sach.py benchmark/holdout-corpus-2.txt  sach/kiemtra2

git stash && python -m archive_guard.benchmark --benign sach/bo1 --no-clamav --out truoc && git stash pop
python -m archive_guard.benchmark --benign sach/bo1 --no-clamav --out sau
```

Lặp lại cho `kiemtra1`, `kiemtra2`, và cho bộ mẫu tổng hợp: `python benchmark/dung_mau_tong_hop.py tonghop/` rồi
`--malicious tonghop/`. Dán bảng
"theo nhóm" và danh sách ca báo nhầm của `truoc.md`/`sau.md` vào PR.

## Quy trình review luật

Người review kiểm tra:

| Câu hỏi | Chặn merge nếu |
|---|---|
| Báo nhầm trên 3 bộ sạch | Có gói nào **mới** bị gắn ĐÁNG NGỜ/NGUY HIỂM mà PR không giải thích và chấp nhận rõ ràng |
| NGUY HIỂM | Có thêm bất kỳ gói sạch nào bị NGUY HIỂM |
| Kỷ luật dữ liệu | Luật được chỉnh để hết báo nhầm trên **bộ kiểm tra 3** (`holdout-corpus-2.txt`) – bộ đó chỉ để đo; chỉnh trên bộ 1 và bộ kiểm tra 1 |
| Mẫu tổng hợp | Mẫu nào trong `tests/positives.py` bị tụt kết luận |
| Một chuỗi đơn lẻ quyết định mức HIGH | Không có bằng chứng bổ trợ hoặc lý do rõ ràng |
| Test hai chiều, `RULE_META` (confidence + ATT&CK), CHANGELOG | Thiếu |
| Luật YARA lấy từ nơi khác | Giấy phép không cho phân phối lại trong repo MIT (GPL, CC BY-NC…), hoặc thiếu nguồn/tác giả |

Khi bộ kiểm tra 3 đã bị dùng để quyết định quá nhiều lần, hãy dựng bộ kiểm tra mới (gói chưa có trong các manifest)
và đo nó bằng luật cũ trước – xem docs/BENCHMARK.md.

## Báo nhầm / bỏ sót

Dùng mẫu issue **"Báo nhầm"** hoặc **"Bỏ sót"**: SHA-256, nguồn công khai (gói + phiên bản, hoặc trang
MalwareBazaar/VirusTotal của mẫu), kết luận nhận được, phát hiện liên quan. Không đính kèm mã độc. Báo nhầm đã xác
nhận được thêm vào bộ phần mềm sạch ở lần đo sau; bỏ sót được dùng để viết luật và đo recall.
