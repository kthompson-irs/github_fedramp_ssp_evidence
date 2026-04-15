#!/usr/bin/env python3
"""Helper script to print the GitHub App installation ID for a target account.

Usage:
  python helpers/get_installation_id.py --target sds-sbx

Required environment variables:
  GH_APP_ID
  GH_APP_PRIVATE_KEY or GH_APP_PRIVATE_KEY_FILE
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests

try:
    import jwt  # PyJWT
except Exception:
    jwt = None

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
except Exception as exc:  # pragma: no cover
    raise SystemExit(
        "cryptography is required to sign the GitHub App JWT. "
        "Install it with: python -m pip install cryptography pyjwt"
    ) from exc


API_BASE = "https://api.github.com"


def read_private_key_pem() -> bytes:
    key_file = os.getenv("GH_APP_PRIVATE_KEY_FILE", "").strip()
    if key_file:
        path = Path(key_file)
        if not path.exists():
            raise SystemExit(f"GitHub App private key file not found: {path}")
        return path.read_text(encoding="utf-8").strip().encode("utf-8")

    raw = os.getenv("GH_APP_PRIVATE_KEY", "").strip()
    if not raw:
        raise SystemExit("GH_APP_PRIVATE_KEY or GH_APP_PRIVATE_KEY_FILE is required.")
    return raw.replace("\r", "").encode("utf-8")


def get_app_id() -> int:
    raw = os.getenv("GH_APP_ID", "").strip()
    if not raw:
        raise SystemExit("GH_APP_ID is required.")
    try:
        return int(raw)
    except ValueError as exc:
        raise SystemExit(f"Invalid GH_APP_ID: {raw}") from exc


def github_headers(token: str) -> Dict[str, str]:
    clean = (token or "").strip().replace("\r", "").replace("\n", "")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "github-app-installation-id-helper/1.0",
    }
    if clean:
        headers["Authorization"] = f"Bearer {clean}"
    return headers


def api_get(path: str, token: str) -> Tuple[int, Any]:
    resp = requests.get(f"{API_BASE}{path}", headers=github_headers(token), timeout=30)
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

    if jwt is not None:
        return jwt.encode(payload, private_key, algorithm="RS256")

    key = serialization.load_pem_private_key(private_key, password=None)
    header = {"alg": "RS256", "typ": "JWT"}

    def b64(data: bytes) -> bytes:
        return base64.urlsafe_b64encode(data).rstrip(b"=")

    header_b64 = b64(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    message = header_b64 + b"." + payload_b64
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return (message + b"." + b64(signature)).decode("utf-8")


def list_installations(app_jwt: str) -> list[dict[str, Any]]:
    status, payload = api_get("/app/installations", app_jwt)
    if status != 200 or not isinstance(payload, list):
        raise SystemExit(f"Failed to list app installations: HTTP {status} {payload}")
    return [item for item in payload if isinstance(item, dict)]


def find_installation_id(app_jwt: str, target: str) -> Optional[int]:
    target_norm = target.strip().lower()

    for inst in list_installations(app_jwt):
        inst_id = inst.get("id")
        account = inst.get("account") or {}
        login = account.get("login") if isinstance(account, dict) else None

        if not isinstance(inst_id, int):
            continue

        if login and login.strip().lower() == target_norm:
            return inst_id

    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Print the GitHub App installation ID for a target account.")
    parser.add_argument("--target", required=True, help="Enterprise or org login to match")
    args = parser.parse_args()

    app_id = get_app_id()
    private_key = read_private_key_pem()
    app_jwt = build_jwt(app_id, private_key)

    installation_id = find_installation_id(app_jwt, args.target)
    if installation_id is None:
        raise SystemExit(f"No installation found for target '{args.target}'.")

    print(installation_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
