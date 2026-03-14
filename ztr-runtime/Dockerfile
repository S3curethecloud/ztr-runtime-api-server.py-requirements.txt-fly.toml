FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# -------------------------------------------------
# Install system dependencies
# -------------------------------------------------
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

# -------------------------------------------------
# Install OPA
# -------------------------------------------------
RUN curl -L -o /usr/local/bin/opa \
    https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static \
 && chmod +x /usr/local/bin/opa

# -------------------------------------------------
# Install Python dependencies
# -------------------------------------------------
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# -------------------------------------------------
# Copy application code
# -------------------------------------------------
COPY . .

RUN mkdir -p /app/policies

# -------------------------------------------------
# Runtime start script
# -------------------------------------------------
COPY start-runtime.sh /start-runtime.sh
RUN chmod +x /start-runtime.sh

# -------------------------------------------------
# Create non-root runtime user
# -------------------------------------------------
RUN useradd -m runtimeuser
USER runtimeuser

EXPOSE 8000

CMD ["/start-runtime.sh"]
