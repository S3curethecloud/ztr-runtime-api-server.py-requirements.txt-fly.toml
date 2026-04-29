#!/bin/sh
set -e

echo "🚀 Starting Runtime..."

# -----------------------------
# Start OPA (ONLY if not using sidecar)
# -----------------------------
if [ "$OPA_ENABLED" != "true" ]; then
  echo "🚀 Starting embedded OPA..."

  opa run --server /app/policies --addr 0.0.0.0:8181 &

  # Give OPA time to boot
  sleep 2
else
  echo "⏳ Waiting for OPA sidecar..."
  until curl -sf http://127.0.0.1:8181/health > /dev/null; do
    sleep 1
  done
  echo "✅ OPA sidecar is ready"
fi

# -----------------------------
# Wait for Redis
# -----------------------------
echo "⏳ Waiting for Redis..."

until python - <<EOF
import redis, os
try:
    r = redis.from_url(os.environ["REDIS_URL"])
    r.ping()
except Exception:
    raise SystemExit(1)
EOF
do
  echo "⏳ waiting for redis..."
  sleep 1
done

echo "✅ Redis is ready"

# -----------------------------
# Start FastAPI
# -----------------------------
echo "🚀 Launching FastAPI..."
exec uvicorn api.server:app --host 0.0.0.0 --port 8000
