FROM python:3.13-slim AS base
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY sentinel ./sentinel
RUN pip install --no-cache-dir fastapi pydantic redis structlog
ENV PYTHONPATH=/app
FROM base AS normaliser
CMD ["python", "-c", "import time; time.sleep(2147483647)"]
FROM base AS detector
CMD ["python", "-c", "import time; time.sleep(2147483647)"]
FROM base AS correlator
CMD ["python", "-c", "import time; time.sleep(2147483647)"]
