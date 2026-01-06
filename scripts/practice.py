from __future__ import annotations
import argparse
import json
import sys
import requests

def main() -> None:
    parser = argparse.ArgumentParser(description="Score a URL using the local URL Trust Scorer API.") #parser holds the instance of the argument parser
    parser.add_argument("url", help="URL to score (e.g., https://example.com)") #url is the positional argument (Make sure the user passes the url)
    parser.add_argument("--port", default=8000, help="API port (default: 8000)") #url is the positional argument (Make sure the user passes the url)
    parser.add_argument("--host", help="API host (default: http://127.0.0.1:8000)") #host is the optional argument (Make sure the user passes the host)
    
    # args = parser.parse_args("url --port 8000 --host http://127.0.0.1:8000") #parser has 2 arguments (url and host) after parsing the args object is basically args.url and args.host
    print("https://google.com --port 8000 --host http://127.0.0.1:8000".split())
    args = parser.parse_args(sys.argv[1:])
    print(type(args.port))
if __name__ == "__main__":
    main()
