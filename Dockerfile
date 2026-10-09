FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements-lock.txt pyproject.toml ./
COPY security_lab ./security_lab
RUN pip install --no-cache-dir -r requirements-lock.txt \
    && pip install --no-cache-dir --no-deps .

ENV LAB_DATA_DIR=/app/data
EXPOSE 8443 8444
CMD ["python", "-m", "security_lab", "serve"]
