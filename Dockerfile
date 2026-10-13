FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY migrations ./migrations
COPY src ./src

EXPOSE 5000

CMD ["sh", "-c", "python src/migrate.py && gunicorn --chdir src --worker-class eventlet -w 1 --bind 0.0.0.0:${PORT:-5000} api_server:app"]
