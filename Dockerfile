# ── Build stage: install Python dependencies ──────────────────────────────────
FROM python:3.13-slim AS base

# System packages needed by xhtml2pdf (PDF rendering) and pypsrp (WinRM)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libssl-dev \
        libxml2-dev \
        libxslt1-dev \
        zlib1g-dev \
        libcairo2-dev \
        pkg-config \
        python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (layer-cached until requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── App stage ─────────────────────────────────────────────────────────────────
# Copy the application code
COPY . .

# Make sure persistent directories exist inside the image
RUN mkdir -p logs reports

# Copy and set up the entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["/entrypoint.sh"]
