FROM python:3.12-slim
ARG TRIVY_VERSION=0.76.2
# trivy for image/filesystem targets; arch-detected so one image works x86+arm
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
 && A=$(uname -m); case "$A" in x86_64) T=64Bit;; aarch64) T=ARM64;; *) T=64Bit;; esac \
 && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${T}.tar.gz" \
    | tar -xz -C /usr/local/bin trivy \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir pyyaml
WORKDIR /app
COPY scan.py fix.py policy.py bastion_core.py /app/
COPY scripts/run.sh /app/run.sh
COPY config/config.example.yaml /app/config/config.yaml
COPY config/incidents.example.yaml /app/config/incidents.example.yaml
VOLUME /data
ENTRYPOINT ["python3", "/app/scan.py"]
