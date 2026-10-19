FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends clamav libmagic1 libyara-dev gcc \
    && freshclam || true
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m scanner && chown -R scanner /app
USER scanner
EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "--timeout", "120", "app:app"]
