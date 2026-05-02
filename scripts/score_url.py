from __future__ import annotations
import argparse
import json
import sys
import requests


def post_score(host: str, url: str) -> dict:
    endpoint = host.rstrip("/") + "/score"
    response = requests.post(endpoint, json={"url": url}, timeout=30)
    response.raise_for_status()
    return response.json()


def print_summary(data: dict) -> None:
    risk = data.get("risk", {})
    print("\n=== URL Trust Scorer ===")
    print(f"URL          : {data.get('url')}")
    print(f"Verdict      : {data.get('verdict')}")
    print(f"Trust score  : {data.get('trust_score')}/100")
    print(f"Prediction   : {data.get('predicted_class')}")
    print(f"Final risk   : {float(risk.get('final', 0.0)):.3f}")
    print(f"ML risk      : {float(risk.get('ml', 0.0)):.3f}")
    if "raw_ml" in risk:
        print(f"Raw ML risk  : {float(risk.get('raw_ml', 0.0)):.3f}")

    reasons = data.get("reasons") or []
    if reasons:
        print("\nReasons:")
        for item in reasons:
            if isinstance(item, dict):
                print(f"- {item.get('message') or item.get('reason') or item}")
            else:
                print(f"- {item}")
    else:
        print("\nReasons: none")


def scan_once(host: str, url: str, raw_json: bool) -> None:
    try:
        data = post_score(host, url)
    except requests.RequestException as e:
        print(f"Request failed: {e}", file=sys.stderr)
        return

    if raw_json:
        print(json.dumps(data, indent=2))
    else:
        print_summary(data)


def interactive_loop(host: str, raw_json: bool) -> None:
    print("URL Trust Scorer terminal scanner")
    print("Paste a URL and press Enter. Type q to quit.\n")

    while True:
        url = input("URL> ").strip()
        if url.lower() in {"q", "quit", "exit"}:
            break
        if not url:
            continue
        scan_once(host, url, raw_json)
        print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Score URLs using the local URL Trust Scorer API.")
    parser.add_argument("url", nargs="?", help="URL to score. Omit for interactive mode.")
    parser.add_argument("--host", default="http://127.0.0.1:8000", help="API host.")
    parser.add_argument("--json", action="store_true", help="Print raw JSON instead of a compact summary.")
    args = parser.parse_args()

    if args.url:
        scan_once(args.host, args.url, args.json)
    else:
        interactive_loop(args.host, args.json)


if __name__ == "__main__":
    main()
