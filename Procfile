FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["sh", "-c", "python -c 'from app import init_db; init_db()' && gunicorn app:app --bind 0.0.0.0:$PORT"]
