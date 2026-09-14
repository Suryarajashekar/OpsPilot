FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OPS_PILOT_DB=/app/data/ops_pilot.db

WORKDIR /app
COPY backend ./backend
COPY frontend ./frontend
COPY data ./data
COPY scripts ./scripts
COPY README.md .

RUN mkdir -p /app/data
EXPOSE 8080
CMD ["python", "backend/server.py"]
