FROM python:3.13-slim
WORKDIR /app
COPY engine /app/engine
COPY api /app/api
RUN pip install --no-cache-dir fastapi uvicorn pydantic redis structlog
ENV PYTHONPATH=/app/engine
EXPOSE 8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
