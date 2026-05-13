# ── Stage 1: build LWN-Simulator for Linux amd64 ────────────────────────────
FROM golang:1.22 AS builder
WORKDIR /src
COPY LWN-Simulator-main/ ./
RUN go install github.com/rakyll/statik@latest \
    && go mod download \
    && cd webserver && statik -f -src=public \
    && cd .. \
    && go build -o lwnsimulator cmd/main.go

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.11-slim

# System packages: tshark for PCAP parsing, graphviz for attack trace images
# Scyther: use pre-built Linux binary from GitHub release (avoids build toolchain)
RUN apt-get update && apt-get install -y --no-install-recommends \
        tshark graphviz wget ca-certificates \
    && wget -qO /tmp/scyther.tgz \
       https://github.com/cascremers/scyther/releases/download/v1.3.0/scyther-linux-v1.3.0.tgz \
    && tar xzf /tmp/scyther.tgz -C /tmp \
    && find /tmp -path "*/Scyther/*" -type f ! -name "*.py" ! -name "__pycache__" \
       | head -1 | xargs -I{} cp {} /usr/local/bin/scyther \
    && chmod +x /usr/local/bin/scyther \
    && apt-get purge -y wget \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /tmp/scyther* \
    && pip install --no-cache-dir cryptography

COPY --from=builder /src/lwnsimulator /app/lwnsimulator
COPY pcap_analysis/ /app/pcap_analysis/
COPY models/ /app/models/
COPY LWN-Simulator-main/config.json /app/LWN-Simulator-main/config.json

WORKDIR /app/pcap_analysis

ENV SCYTHER_BIN=/usr/local/bin/scyther \
    LOOPBACK_IFACE=lo

# Default: run synthetic validation suite. Override CMD to use other modes:
#   docker run faol python3 lwn_validator.py --pcap /data/capture.pcap
ENTRYPOINT ["python3", "lwn_validator.py"]
