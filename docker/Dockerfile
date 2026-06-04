# WebScan — Dockerfile
# Build context must be the webscan/ directory:
#   docker build -f docker/Dockerfile -t webscan .

FROM python:3.11-slim

# ── System dependencies ────────────────────────────────────────────────────
# nmap       : port scanning (scanner/recon/port_scan.py)
# chromium   : placeholder — Playwright installs its own bundled Chromium,
#              but system libs are required (handled by `playwright install --with-deps`)
# build deps : needed by weasyprint (pango, cairo) and cryptography (gcc)
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        gcc \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libcairo2 \
        libgdk-pixbuf2.0-0 \
        libffi-dev \
        libssl-dev \
        fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Python dependencies ────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright's bundled Chromium + all required OS libraries in one step
RUN playwright install --with-deps chromium

# ── Application code ───────────────────────────────────────────────────────
COPY . .

# Ensure `import scanner.*` and `import config` resolve from /app
ENV PYTHONPATH=/app

# Output directories (volumes will overlay these at runtime)
RUN mkdir -p logs reports wordlists

# ── Entrypoint ─────────────────────────────────────────────────────────────
ENTRYPOINT ["python", "main.py"]
