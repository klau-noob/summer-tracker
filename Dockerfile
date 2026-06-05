FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY static/ static/

# /data is expected to be a mounted persistent volume
VOLUME ["/data"]

ENV DB_PATH=/data/tracker.db
ENV PORT=8000

EXPOSE 8000

CMD ["python", "main.py"]
