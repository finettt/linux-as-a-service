FROM python:3.11-slim

WORKDIR /app

COPY requirements/common.txt .
RUN pip install --upgrade pip && \
    pip install -r common.txt

COPY . .

CMD ["gunicorn", "--workers", "1", "--bind","0.0.0.0:8000", "wsgi:app"]