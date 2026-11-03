# Hướng dẫn cho người giữ repo

Mọi việc chỉ người có quyền ghi vào repo mới làm: phát hành, cài đặt repo, việc bảo trì định kỳ. Người đóng góp
đọc [CONTRIBUTING.md](../CONTRIBUTING.md).

## Thiết lập một lần

| Việc | Ở đâu | Trạng thái |
|---|---|---|
| Bật **Private vulnerability reporting** (SECURITY.md dẫn tới đây) | Settings → Code security | ⚠️ đang tắt |
| Khóa ký tag: `git config --global gpg.format ssh`, `git config --global user.signingkey ~/.ssh/id_ed25519.pub`; thêm khóa vào GitHub dưới dạng **Signing key** | Settings (tài khoản) → SSH and GPG keys | |
| Bắt buộc tag có chữ ký | Settings → Rules → Rulesets → nhắm vào tag → Require signed commits | tùy chọn |
| Môi trường `pypi`, bật *Required reviewers* | Settings → Environments | |
| PyPI Trusted Publisher: project `archive-guard`, owner `nakame9`, repo `archive-guard`, workflow `release.yml`, environment `pypi` | pypi.org → Account settings → Publishing | |
| Secret `ABUSECH_AUTH_KEY` (workflow `update-hashes`) | Settings → Secrets and variables → Actions | ✅ |
| Nhãn issue `báo nhầm`, `bỏ sót` (mẫu issue gắn tự động) | Issues → Labels | ✅ |

## Phát hành

1. Chuyển `[Chưa phát hành]` trong `CHANGELOG.md` thành `[X.Y.Z] – ngày`.
2. Tăng `version` (`pyproject.toml`) và `__version__` (`archive_guard/__init__.py`); cập nhật số phiên bản trong
   ví dụ của `docs/INTEGRATION.md` và trong `docs/ROADMAP.md`.
3. Commit, đợi CI xanh, gắn **tag có chữ ký**: `git tag -s vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`.
4. Workflow `release` tự build, sinh SBOM, ký Sigstore + provenance (và tự xác minh), đăng PyPI (chờ duyệt ở môi
   trường `pypi`), tạo GitHub Release. Tag khác `version` trong `pyproject.toml` thì dừng ngay.
   Chạy thử không phát hành: Actions → release → Run workflow.

## Việc định kỳ

| Khi nào | Việc |
|---|---|
| Mỗi tuần | Duyệt PR của Dependabot (pip, GitHub Actions, digest Docker); CI chạy pip-audit trên từng PR |
| Khi CI đỏ ở job `audit` lúc không ai sửa code | Có CVE mới trong dependency: cập nhật bản vá (xem bên dưới) |
| Mỗi ngày (tự động) | `update-hashes`: ký + đăng Release `hash-db`; thứ Hai commit vào `main`. Xem lại nếu workflow đỏ (Auth-Key hết hạn, API đổi) |
| Khi có bản unrar mới / CVE của unrar | Cập nhật 4 dòng `UNRAR_*` trong `Dockerfile` (hướng dẫn ngay trong file) |
| Vài tháng một lần | Cập nhật luật signature-base (`archive_guard/data/rules/signature-base/README.md`, nhớ sửa `VERSION`), đo lại báo nhầm |
| Khi bộ kiểm tra 3 đã bị nhìn quá nhiều | Dựng bộ kiểm tra mới, đo bằng luật cũ trước ([BENCHMARK.md](BENCHMARK.md)) |
| Sau mỗi lần thử nghiệm trên nhánh tạm | Xóa nhánh `tmp/*` |

## Cập nhật dependency

Lock file được tạo bằng `uv` đã pin (job `audit` kiểm tra lock khớp `pyproject.toml`):

```bash
pip install --require-hashes -r .github/requirements-tools.txt
uv pip compile pyproject.toml --extra yara --universal --python-version 3.10 --generate-hashes -o requirements.txt
uv pip compile pyproject.toml --extra yara --extra update --extra dev --universal --python-version 3.10 --generate-hashes -o requirements-dev.txt
uv pip compile .github/requirements-tools.in --python-version 3.13 --generate-hashes -o .github/requirements-tools.txt
```

Thêm `--upgrade-package <tên>` để nâng một gói; chạy `pip-audit --disable-pip --require-hashes -r requirements-dev.txt`
trước khi commit.

## Tài liệu: mỗi thông tin ở đúng một chỗ

| Thông tin | Chỉ sửa ở | Nơi khác chỉ dẫn link |
|---|---|---|
| Tùy chọn dòng lệnh, JSON, sandbox theo hệ điều hành | `docs/USAGE.md` | README, TROUBLESHOOTING |
| Luật, cách chấm điểm | `docs/RULES.md` | CONTRIBUTING |
| Số liệu đo | `docs/BENCHMARK.md` (README chỉ giữ 1 đoạn tóm tắt) | README |
| Chính sách báo lỗ hổng | `SECURITY.md` | README, CONTRIBUTING |
| Mô hình bảo mật, chuỗi cung ứng, xác minh bản phát hành | `docs/SECURITY-MODEL.md` | SECURITY.md |
| Giấy phép bên thứ ba | `THIRD_PARTY_NOTICES.md` | README, CONTRIBUTING |
| Việc của người giữ repo | file này | CONTRIBUTING |
