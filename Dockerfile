FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    DISPATCH_METHOD=smtp \
    SMTP_HOST=127.0.0.1 \
    SMTP_PORT=25

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --root-user-action=ignore -r requirements.txt \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin dmarc \
    && rm -rf /root/.cache

COPY src/dmarc_analyzer.py .

USER dmarc

ENTRYPOINT ["python", "/app/dmarc_analyzer.py"]
