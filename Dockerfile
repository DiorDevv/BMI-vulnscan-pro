FROM python:3.12-slim

LABEL maintainer="VulnScan Pro" \
      description="Production-grade async web vulnerability scanner"

# Install system dependencies (nmap for port scanning)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        libssl-dev \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .
RUN pip install --no-cache-dir -e .

# Create non-root user for security
RUN useradd -m -u 1000 vulnscan && \
    mkdir -p /reports && \
    chown vulnscan:vulnscan /reports /app

USER vulnscan

VOLUME ["/reports"]

ENTRYPOINT ["vulnscan"]
CMD ["--help"]
