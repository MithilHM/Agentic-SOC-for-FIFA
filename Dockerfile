# Dockerfile — FIFA AI-SIEM
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Train model on container build so pipeline.worker can load it
RUN python -m ml.train_model || true

EXPOSE 8080

CMD ["uvicorn", "api.server:app", "--host", "0.0.0.0", "--port", "8080"]
