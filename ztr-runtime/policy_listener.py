import json
import redis
import os
import threading

REDIS_URL = os.environ["REDIS_URL"]

r = redis.from_url(REDIS_URL, decode_responses=True)


def handle_policy_update(message):
    try:
        data = json.loads(message["data"])

        tenant_id = data.get("tenant_id")
        version = data.get("policy_version")

        print(f"[POLICY SYNC] tenant={tenant_id} version={version}")

        # 🔒 IMPORTANT:
        # DO NOT trust event payload as source of truth
        # Always re-read from Redis

        policy = r.hgetall(f"tenant:{tenant_id}:policy")

        print(f"[POLICY REFRESHED] {policy}")

        # Future hook:
        # reload local cache / invalidate in-memory state

    except Exception as e:
        print("[POLICY ERROR]", str(e))


def start_policy_listener():
    pubsub = r.pubsub()
    pubsub.subscribe("policy_updates")

    print("[POLICY LISTENER] started")

    for message in pubsub.listen():
        if message["type"] == "message":
            handle_policy_update(message)


def start_listener_thread():
    thread = threading.Thread(target=start_policy_listener, daemon=True)
    thread.start()
