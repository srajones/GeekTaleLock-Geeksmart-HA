# syntax=docker/dockerfile:1
ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.11-alpine3.19
FROM ${BUILD_FROM}

WORKDIR /app

COPY requirements.txt /app/requirements.txt

RUN apk add --no-cache \
        bash \
        jq \
    && apk add --no-cache --virtual .build-deps \
        gcc \
        musl-dev \
        libffi-dev \
        openssl-dev \
        cargo \
    && pip install --no-cache-dir -r /app/requirements.txt \
    && apk del .build-deps

COPY client/ /app/client/
COPY custom_components/ /app/custom_components/
COPY server/ /app/server/
COPY scripts/ /app/scripts/
COPY door_lock_control.py /app/door_lock_control.py

# Support building from both repository root and add-on subdirectory (COPY run.sh /run.sh)
COPY geek_door_addon/run.sh run.sh* /run.sh
RUN chmod +x /run.sh

EXPOSE 5050

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5050/api/health', timeout=4)" || exit 1

CMD ["/run.sh"]
