# Tích hợp vào CI/CD

Chọn ngưỡng thất bại bằng `--fail-on` ([USAGE.md](USAGE.md#--fail-on-ngưỡng-thất-bại-của-pipeline)). Khuyến nghị cho
pipeline: `--fail-on malicious,incomplete`, tức chặn thứ chắc chắn xấu **và** thứ chưa kiểm tra được; để người
xem lại những gì ĐÁNG NGỜ qua báo cáo JSON.

> Cài đúng phiên bản đã kiểm tra: dùng tag phát hành (vd. `v0.17.0`) và `requirements.txt` có hash của chính tag
> đó. Đừng cài từ nhánh `main` cho pipeline production.

## GitHub Actions

```yaml
# .github/workflows/archiveguard.yml – quét mọi file nén trong repo/thư mục tải về
name: archiveguard
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest  # Linux x86_64: đủ sandbox (Landlock + seccomp + network namespace)
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0
        with:
          python-version: "3.13"
      - name: Cài ArchiveGuard v0.17.0 (dependency kiểm tra hash) + unrar
        run: |
          git clone --depth 1 --branch v0.17.0 https://github.com/nakame9/archive-guard.git "$RUNNER_TEMP/ag"
          python -m pip install --require-hashes -r "$RUNNER_TEMP/ag/requirements.txt"
          python -m pip install --no-deps "$RUNNER_TEMP/ag"
          sudo apt-get install -y -q unrar
      - name: Quét
        run: |
          archiveguard . --require-sandbox --no-clamav --fail-on malicious,incomplete \
            --json archiveguard.json
      - name: Lưu báo cáo (cả khi bước quét thất bại)
        if: always()
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: archiveguard-report
          path: archiveguard.json
```

- Chỉ quét file thay đổi trong PR: thay `.` bằng danh sách từ
  `git diff --name-only --diff-filter=AM origin/${{ github.base_ref }}...HEAD` (cần `fetch-depth: 0`).
- `--require-sandbox` làm job thất bại nếu runner không có sandbox (vd. runner tự host chạy Windows) – an toàn hơn
  là âm thầm quét không sandbox.

## GitLab CI

```yaml
# .gitlab-ci.yml
archiveguard:
  image: python:3.13-slim
  variables:
    AG_VERSION: v0.17.0
  before_script:
    # unrar nằm ở thành phần non-free của Debian
    - 'sed -i "s/^Components: main$/Components: main non-free/" /etc/apt/sources.list.d/debian.sources'
    - apt-get update -q && apt-get install -y -q --no-install-recommends git unrar
    - git clone --depth 1 --branch "$AG_VERSION" https://github.com/nakame9/archive-guard.git /opt/ag
    - python -m pip install --require-hashes -r /opt/ag/requirements.txt
    - python -m pip install --no-deps /opt/ag
  script:
    - archiveguard . --no-clamav --fail-on malicious,incomplete --json archiveguard.json --stats archiveguard.prom
  artifacts:
    when: always
    paths: [archiveguard.json, archiveguard.prom]
```

Runner Docker của GitLab thường không cho tạo user namespace (`network_namespace: không được`), nhưng Landlock và
seccomp vẫn bật trên host Linux x86_64, nên `--require-sandbox` vẫn dùng được. Dòng `Sandbox của worker: …` cuối
log cho biết chính xác.

## pre-commit

Chặn commit thêm file nén nguy hiểm hoặc chưa kiểm tra được vào repo:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/nakame9/archive-guard
    rev: v0.17.0
    hooks:
      - id: archiveguard
        # mặc định: --no-clamav --fail-on malicious,incomplete; đổi bằng args, vd. chặn cả ĐÁNG NGỜ:
        # args: [--no-clamav]
        additional_dependencies: [yara-python]  # luật YARA + dò chuỗi nhanh hơn (bỏ nếu không cài được)
```

Hook chỉ chạy với file nén theo đuôi (`.zip .rar .7z .tar .gz .jar .whl .apk .docx/.docm/.xlsx/.xlsm …`). pre-commit
cài dependency từ `pyproject.toml`, **không** kiểm tra hash như `requirements.txt`. File RAR cần `unrar` trên máy
người commit, nếu không sẽ ra CHƯA QUÉT ĐỦ và hook thất bại.

## Docker (mọi hệ thống CI)

```bash
docker build --no-cache -t archive-guard https://github.com/nakame9/archive-guard.git#v0.17.0
docker run --rm --network none --read-only --tmpfs /tmp:rw,size=1g --cap-drop ALL \
  --security-opt no-new-privileges --memory 2g --pids-limit 128 \
  -v "$PWD:/scan:ro" archive-guard . --fail-on malicious,incomplete
```

Image đã có `unrar`, mọi thành phần được pin (xem SECURITY.md). Đây là cách duy nhất có sandbox file/mạng cho runner
Windows (Docker Desktop/WSL2).

## Kết quả cho người xem lại

- `--json FILE`: báo cáo đầy đủ; `reports[].verdict`, `reports[].files[].findings[]` (mã luật, `confidence`, mã
  MITRE ATT&CK). Định dạng ổn định theo `schema_version`.
- `--stats FILE`: số liệu Prometheus cho Grafana ([USAGE.md](USAGE.md#--stats-số-liệu-cho-prometheusgrafana)).
- Báo nhầm lặp lại với một công cụ bạn tin dùng: thêm SHA-256 vào `--allowlist` (đưa file allowlist vào Git cùng
  pipeline) **và** mở issue "Báo nhầm" để luật được sửa.
