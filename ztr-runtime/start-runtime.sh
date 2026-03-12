#!/bin/sh

set -e

echo "Starting OPA..."
opa run --server --addr :8181 /app/policies &

echo "Starting SecureTheCloud Runtime..."
exec uvicorn api.server:app --host 0.0.0.0 --port 8000
