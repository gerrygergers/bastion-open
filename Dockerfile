FROM python:3.12-slim
# Supply-chain hygiene: trivy is pinned by version and verified against the
# release's published checksums.txt (HTTPS) at build time; the build FAILS if
# the archive doesn't match. Bump TRIVY_VERSION deliberately.
ARG TRIVY_VERSION=0.76.2
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates xz-utils openssh-client openssl; \
    A=$(uname -m); case "$A" in \
      x86_64) T=64Bit;; aarch64) T=ARM64;; armv7l) T=ARM;; \
      *) echo "unsupported arch $A" && exit 1;; esac; \
    cd /tmp; \
    curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"; \
    FILE="trivy_${TRIVY_VERSION}_Linux-${T}.tar.gz"; \
    curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${FILE}"; \
    grep " ${FILE}\$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "$FILE" trivy; mv trivy /usr/local/bin/trivy; \
    rm -f "$FILE" "trivy_${TRIVY_VERSION}_checksums.txt"; \
    apt-get purge -y --auto-remove curl xz-utils; \
    rm -rf /var/lib/apt/lists/*; \
    pip install --no-cache-dir pyyaml==6.0.3; \
    useradd -r -u 10001 -d /data bastion; \
    trivy --version | head -1
WORKDIR /app
COPY scan.py fix.py policy.py bastion_core.py bastion.py /app/
COPY scripts/run.sh /app/run.sh
COPY config/config.example.yaml /app/config/config.yaml
COPY config/config.example.json /app/config/config.example.json
COPY config/incidents.example.yaml /app/config/incidents.example.yaml
RUN mkdir -p /data && chmod 1777 /data \
 && chmod -R a+rX /app
VOLUME /data
# Runs as root with ALL capabilities dropped except DAC_READ_SEARCH (the one
# syscall-bypass cap needed to read host /etc/shadow for two auth checks).
# Verified on docker 29: non-root + ambient caps does NOT work (caps drop at
# setuid), so this is the honest shape. Drop the cap_add for a tighter,
# partial scan — shadow-based checks then emit scan-gap findings, never passes.
USER 0
ENTRYPOINT ["python3", "/app/scan.py"]
