FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN groupadd --system app && useradd --system --gid app --home-dir /app app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY alembic.ini ./
COPY migrations ./migrations
COPY app ./app
RUN chown -R app:app /app
USER app
EXPOSE 8000
# --forwarded-allow-ips is intentionally NOT "*": that would trust
# X-Forwarded-For/X-Forwarded-Proto from *any* client able to reach this
# container directly, letting a request spoof its own source_ip in audit
# logs and rate-limit keys. In this Compose topology the backend is only
# reachable from the frontend/nginx (or Caddy in production) container on
# the internal application network, so it is limited to well-known
# private ranges instead -- broad enough that no per-deployment
# configuration is needed, but excludes the public internet.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2 --proxy-headers --forwarded-allow-ips=127.0.0.1,172.16.0.0/12,10.0.0.0/8,192.168.0.0/16"]
