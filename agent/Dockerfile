# AgentCore Runtime requires ARM64 (AWS Graviton) -- build with:
#   docker buildx build --platform linux/arm64 --provenance=false -t <repo>:latest .
# (--provenance=false for the same reason as daily-tech-brief-bedrock: a
# buildx attestation manifest produces a multi-manifest image that AWS's
# container runtimes reject.)
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Host/port per the AgentCore Runtime HTTP protocol contract.
EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
