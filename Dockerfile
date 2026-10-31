# Image chạy ArchiveGuard trong container cứng hóa. Cách chạy khuyến nghị (docs/USAGE.md#docker):
#   docker run --rm --network none --read-only --tmpfs /tmp:rw,size=1g --cap-drop ALL \
#     --security-opt no-new-privileges --memory 2g --pids-limit 128 -v "$PWD:/scan:ro" archive-guard .
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY archive_guard ./archive_guard
RUN pip install --no-cache-dir ".[yara]" \
    && rm -rf /src \
    && useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin scanner

# Không chạy bằng root; thư mục cần quét được gắn chỉ-đọc vào /scan
USER 10001
WORKDIR /scan
ENTRYPOINT ["archiveguard"]
CMD ["--help"]
