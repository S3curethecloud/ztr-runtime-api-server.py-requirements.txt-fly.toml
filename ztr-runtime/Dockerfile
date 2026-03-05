FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install OPA
RUN apt-get update && apt-get install -y curl \
 && curl -L -o /usr/local/bin/opa \
    https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static \
 && chmod +x /usr/local/bin/opa

COPY . .

EXPOSE 8000

CMD sh -c "\
opa run --server --addr :8181 /app/policies & \
uvicorn api.server:app --host 0.0.0.0 --port 8000"
