# Image chạy ArchiveGuard trong container cứng hóa. Cách chạy khuyến nghị (docs/USAGE.md#docker):
#   docker run --rm --network none --read-only --tmpfs /tmp:rw,size=1g --cap-drop ALL \
#     --security-opt no-new-privileges --memory 2g --pids-limit 128 -v "$PWD:/scan:ro" archive-guard .
# Build: docker build --no-cache -t archive-guard .  (--no-cache: không dùng lại lớp cũ build từ nội dung khác)
#
# Mọi thứ đi vào image đều được pin:
# - base image theo digest (Dependabot mở PR khi python:3.13-slim có bản mới)
# - thư viện Python theo requirements.txt có hash (--require-hashes)
# - unrar theo phiên bản + SHA-256, tải từ snapshot.debian.org (URL không đổi nội dung theo thời gian)
FROM python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1

# unrar để đọc NỘI DUNG file RAR (Debian trixie, non-free). Cập nhật: đổi 4 dòng dưới theo bản mới trên
# https://snapshot.debian.org/package/unrar-nonfree/ và kiểm tra lại SHA-256. unrar có lịch sử CVE: xem SECURITY.md.
ARG UNRAR_SNAPSHOT=20261101T000000Z
ARG UNRAR_VERSION=7.1.8-1
ARG UNRAR_SHA256_AMD64=ad50191c24ef8334ce4f12ac8a11c30faa773651215966d868c3b7c24e1f73f6
ARG UNRAR_SHA256_ARM64=dc577cd19a671425c399d8f58afde991508d8903fa30db1ffe4f9d575fe18f4b

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /src
COPY requirements.txt pyproject.toml README.md LICENSE ./
COPY archive_guard ./archive_guard
RUN set -eu; \
    arch=$(dpkg --print-architecture); \
    case "$arch" in \
      amd64) sum=$UNRAR_SHA256_AMD64 ;; \
      arm64) sum=$UNRAR_SHA256_ARM64 ;; \
      *) echo "chưa pin unrar cho kiến trúc $arch" >&2; exit 1 ;; \
    esac; \
    python -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], '/tmp/unrar.deb')" \
      "https://snapshot.debian.org/archive/debian/$UNRAR_SNAPSHOT/pool/non-free/u/unrar-nonfree/unrar_${UNRAR_VERSION}_$arch.deb"; \
    echo "$sum  /tmp/unrar.deb" | sha256sum -c -; \
    dpkg -i /tmp/unrar.deb; \
    rm /tmp/unrar.deb; \
    unrar | head -n 2; \
    pip install --no-cache-dir --require-hashes -r requirements.txt; \
    pip install --no-cache-dir --no-deps .; \
    rm -rf /src; \
    useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin scanner

# Không chạy bằng root; thư mục cần quét được gắn chỉ-đọc vào /scan
USER 10001
WORKDIR /scan
ENTRYPOINT ["archiveguard"]
CMD ["--help"]
