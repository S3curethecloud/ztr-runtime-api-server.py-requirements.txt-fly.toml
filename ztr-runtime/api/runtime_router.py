import hashlib
import redis
import os

r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)


def get_runtime_nodes():
    nodes = list(r.smembers("runtime:nodes"))
    nodes.sort()
    return nodes


def select_runtime_node(key: str):

    nodes = get_runtime_nodes()

    if not nodes:
        return None

    h = int(hashlib.sha256(key.encode()).hexdigest(), 16)

    idx = h % len(nodes)

    return nodes[idx]
