FROM python:3.11-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY . .

# Fly.io / Render / Railway typically set PORT env var
ENV PORT=8001
EXPOSE 8001

# Use shell form so $PORT expands
CMD uvicorn server:app --host 0.0.0.0 --port $PORT
