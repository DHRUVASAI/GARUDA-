# Use official lightweight Python image
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
RUN pip install --no-cache-dir flask flask-cors web3

# Copy project files
COPY . /app

EXPOSE 5000

ENV PORT=5000
ENV HOST=0.0.0.0

CMD ["python", "garuda_backend.py"]
