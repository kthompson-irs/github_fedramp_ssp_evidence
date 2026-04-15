#!/usr/bin/env python3
"""
Helper script to retrieve the GitHub App installation ID.

Usage:
  python get_installation_id.py --target internal-revenue-service

Requires:
  GH_APP_ID
  GH_APP_PRIVATE_KEY (or GH_APP_PRIVATE_KEY_FILE)
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import requests

try:
    import jwt
except Exception:
    jwt = None

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


API_BASE = "https://api.github.com"


def read_private_key() -> bytes:
    raw = os.getenv("GH_APP_PRIVATE_KEY", "").strip()
    if not raw:
        raise SystemExit("❌ GH_APP_PRIVATE_KEY not set")
    return raw.replace("\r", "").encode("utf-8")


def get_app_id() -> int:
    raw = os.getenv("GH_APP_ID", "").strip()
    if not raw:
        raise SystemExit("❌ GH_APP_ID not set")
    return int(raw)


def github_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token.strip()}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def api_get(path: str, token: str) -> Tuple[int, Any]:
    url = f"{API_BASE}{path}"
    resp = requests.get(url, headers=github_headers(token), timeout=30)
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, resp.text


def build_jwt(app_id: int, private_key: bytes) -> str:
    now = datetime.now(timezone.utc)

    payload = {
        "iat": int((now - timedelta(seconds=60)).timestamp()),
        "exp": int((now + timedelta(minutes=9)).timestamp()),
        "iss": str(app_id),
    }

    if jwt:
        return jwt.encode(payload, private_key, algorithm="RS256")

    key = serialization.load_pem_private_key(private_key, password=None)

    header = {"alg": "RS256", "typ": "JWT"}

    def b64(data: bytes):
        return base64.urlsafe_b64encode(data).rstrip(b"=")

    header_b64 = b64(json.dumps(header).encode())
    payload_b64 = b64(json.dumps(payload).encode())
    message = header_b64 + b"." + payload_b64

    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    return (message + b"." + b64(signature)).decode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="Enterprise or org name")
    args = parser.parse_args()

    app_id = get_app_id()
    private_key = read_private_key()

    print("🔐 Generating GitHub App JWT...")
    jwt_token = build_jwt(app_id, private_key)

    print("📡 Fetching installations...")
    status, data = api_get("/app/installations", jwt_token)

    if status != 200:
        raise SystemExit(f"❌ Failed to list installations: {status} {data}")

    print("\n🔍 Searching for installation:\n")

    found = False

    for inst in data:
        inst_id = inst.get("id")
        account = inst.get("account", {})
        login = account.get("login")
        account_type = account.get("type")

        print(f"➡️  Found installation:")
        print(f"   ID: {inst_id}")
        print(f"   Account: {login}")
        print(f"   Type: {account_type}")
        print()

        if login == args.target:
            found = True
            print("✅ MATCH FOUND")
            print(f"👉 Installation ID for '{args.target}': {inst_id}\n")

    if not found:
        print("❌ No matching installation found.")
        print("👉 This means one of the following:")
        print("   - App is NOT installed on the enterprise")
        print("   - App is installed only on orgs/repos")
        print("   - Wrong enterprise slug")


if __name__ == "__main__":
    main()
