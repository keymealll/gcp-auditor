FROM python:3.12-slim AS base

LABEL maintainer="Abdullah Kamil"
LABEL org.opencontainers.image.source="https://github.com/abdullahkamil/gcp-auditor"
LABEL org.opencontainers.image.description="GCP security scanner with 30+ checks mapped to ISO 27001, SOC 2, and CIS benchmarks"

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir .

ENTRYPOINT ["gcp-auditor"]
CMD ["--help"]
