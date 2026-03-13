import os
import socket
import hashlib


def get_node_id():

    node = os.getenv("NODE_ID")

    if node:
        return node

    hostname = socket.gethostname()

    digest = hashlib.sha256(hostname.encode()).hexdigest()

    return f"runtime-{digest[:8]}"
