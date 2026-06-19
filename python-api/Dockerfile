FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

RUN adduser --disabled-password --gecos '' --uid 1000 nmapper

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=nmapper:nmapper . .

RUN mkdir -p /app/scans && chown nmapper:nmapper /app/scans

USER nmapper

EXPOSE 8001

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "1", "--no-access-log"]
