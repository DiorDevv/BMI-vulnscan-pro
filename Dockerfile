FROM python:3.12-slim

LABEL maintainer="VulnScan Pro" \
      description="Production-grade async web vulnerability scanner"

# System dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        libssl-dev \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python dependencies (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application source
COPY . .
RUN pip install --no-cache-dir -e .

# Non-root user
RUN useradd -m -u 1000 vulnscan && \
    mkdir -p /data && \
    chown vulnscan:vulnscan /data /app

USER vulnscan

# SQLite bazasi /data papkasiga yoziladi
ENV DB_PATH=/data/vulnscan.db

# PORT ni Render avtomatik beradi (standart: 10000)
ENV PORT=10000

EXPOSE 10000

# Web UI ni ishga tushirish
CMD ["python", "-c", "from vulnscan.web.app import start_server; start_server(open_browser=False)"]
