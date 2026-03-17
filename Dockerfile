FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install --no-cache-dir "poetry>=2.0.0"

# Copy dependency files
COPY pyproject.toml poetry.lock ./

# Install dependencies (no virtualenv inside container)
RUN poetry config virtualenvs.create false \
    && poetry install --no-root --no-interaction

# Copy application code
COPY . .

# Default: run the API (overridden per-service in docker-compose.yml)
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
