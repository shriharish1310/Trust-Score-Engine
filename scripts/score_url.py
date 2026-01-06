from __future__ import annotations
import argparse
import json
import sys
import requests

def main() -> None:
    parser = argparse.ArgumentParser(description="Score a URL using the local URL Trust Scorer API.") 
    parser.add_argument("url", help="URL to score (e.g., https://example.com)") 
    parser.add_argument("--host", default="http://127.0.0.1:8000", help="API host (default: http://127.0.0.1:8000)") 
    args = parser.parse_args() #args is an object and has args.url and args.host

    endpoint = args.host.rstrip("/") + "/score"

    try:
        r = requests.post(endpoint, json={"url": args.url}, timeout=15)
        r.raise_for_status()
        data = r.json()
        print(json.dumps(data, indent=2))
    except requests.RequestException as e:
        print(f"Request failed: {e}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
