# docker/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy package
COPY dvara/ ./dvara/

# Create filter directory
RUN mkdir -p /app/.dvara

EXPOSE 7860
CMD ["python", "-m", "uvicorn", "dvara.app:app", "--host", "0.0.0.0", "--port", "7860"]
