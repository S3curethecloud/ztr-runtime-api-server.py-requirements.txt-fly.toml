FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN apt-get update \
 && apt-get install -y curl \
 && curl -L -o /usr/local/bin/opa \
    https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static \
 && chmod +x /usr/local/bin/opa \
 && rm -rf /var/lib/apt/lists/*

COPY . .

RUN mkdir -p /app/policies

COPY start-runtime.sh /start-runtime.sh
RUN chmod +x /start-runtime.sh

EXPOSE 8000

CMD ["/start-runtime.sh"]
