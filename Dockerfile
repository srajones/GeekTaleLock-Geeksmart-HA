# syntax=docker/dockerfile:1
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOST=0.0.0.0 \
    PORT=5050 \
    GEEK_DOOR_SESSION_CACHE=/app/data/.session_cache.json

WORKDIR /app

# Create isolated non-root runtime user and persistent session directory
RUN groupadd --gid 10001 geekdoor \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin geekdoor \
    && mkdir -p /app/data \
    && chown -R geekdoor:geekdoor /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY --chown=geekdoor:geekdoor custom_components/ /app/custom_components/
COPY --chown=geekdoor:geekdoor client/ /app/client/
COPY --chown=geekdoor:geekdoor server/ /app/server/
COPY --chown=geekdoor:geekdoor scripts/ /app/scripts/
COPY --chown=geekdoor:geekdoor tests/ /app/tests/
COPY --chown=geekdoor:geekdoor door_lock_control.py hacs.json repository.json /app/

USER geekdoor

EXPOSE 5050

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5050/api/health', timeout=4)" || exit 1

# Single worker with 4 threads preserves in-memory rate-limit timestamps and state overrides
# while handling concurrent REST API + dashboard requests cleanly.
CMD ["gunicorn", "--bind", "0.0.0.0:5050", "--workers", "1", "--threads", "4", "--timeout", "30", "server.app:app"]
