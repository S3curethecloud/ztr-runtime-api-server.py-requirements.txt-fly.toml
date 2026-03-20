from aegis_core import process_event
import requests
import json

STREAM_URL = "https://ztr-runtime.fly.dev/v1/decisions/stream"
API_KEY = "YOUR_KEY"


def run():
    headers = {"X-Stc-Api-Key": API_KEY}

    print("[AEGIS] Connecting...")

    with requests.get(STREAM_URL, headers=headers, stream=True) as resp:
        print("[AEGIS] Connected:", resp.status_code)

        for line in resp.iter_lines():
            if line:
                decoded = line.decode()

                if "data:" in decoded:
                    event = json.loads(decoded.split("data:",1)[1].strip())
                    process_event(event)


if __name__ == "__main__":
    run()
