#!/usr/bin/env python3

import base64
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path


API = "https://api.github.com"
OUT_DIR = Path("evidence/ra08")


RA08_AUDIT_KEYWORDS = [
    "audit_log",
    "business",
    "enterprise",
    "integration",
    "oauth",
    "org",
    "personal_access_token",
    "private_repository",
    "repo",
    "repository",
    "saml",
    "scim",
    "secret_scanning",
    "security",
    "sso",
    "team",
    "user",
]


PII_REVIEW_KEYWORDS = [
    "pii",
    "privacy",
    "pia",
    "pta",
    "privacy impact assessment",
    "privacy threshold analysis",
    "personally identifiable information",
    "sorn",
    "records notice",
]


CANDIDATE_PATHS = [
    "PRIVACY.md",
    "PIA.md",
    "PTA.md",
    "SECURITY.md",
    "CODEOWNERS",
    ".github/CODEOWNERS",
    ".github/ISSUE_TEMPLATE/privacy_review.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    "docs/privacy.md",
    "docs/pia.md",
    "docs/pta.md",
]


def required_env(name: str) -> str:
    value = os.getenv(name, "").strip()

    if not value:
        print(f"ERROR: Missing required environment variable: {name}", file=sys.stderr)
        sys.exit(1)

    return value


TOKEN = required_env("GH_TOKEN_RA08")
ENTERPRISE = required_env("GH_ENTERPRISE")
ORG = required_env("GH_ORG")

AUDIT_DAYS = int(os.getenv("AUDIT_DAYS", "90"))
AUDIT_SCOPE = os.getenv("AUDIT_SCOPE", "org").strip().lower()


def github_headers() -> dict:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ra08-evidence-collector",
    }


def build_url(url: str, params: dict | None = None) -> str:
    if not params:
        return url

    query = urllib.parse.urlencode(params)
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{query}"


def parse_link_header(value: str | None) -> dict:
    links = {}

    if not value:
        return links

    for part in value.split(","):
        section = part.strip().split(";")

        if len(section) < 2:
            continue

        url = section[0].strip()

        if url.startswith("<") and url.endswith(">"):
            url = url[1:-1]

        rel = None

        for item in section[1:]:
            item = item.strip()

            if item.startswith("rel="):
                rel = item.split("=", 1)[1].strip('"')

        if rel:
            links[rel] = url

    return links


def request_json(url: str, params: dict | None = None):
    final_url = build_url(url, params)

    while True:
        request = urllib.request.Request(
            final_url,
            headers=github_headers(),
            method="GET",
        )

        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                body = response.read().decode("utf-8")
                headers = dict(response.headers.items())

                if not body:
                    return None, headers

                return json.loads(body), headers

        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            headers = dict(error.headers.items())

            if error.code in (403, 429):
                remaining = headers.get("X-RateLimit-Remaining")
                reset = headers.get("X-RateLimit-Reset")

                if remaining == "0" and reset:
                    sleep_for = max(
                        5,
                        int(reset) - int(time.time()) + 5,
                    )

                    print(
                        f"Rate limited. Sleeping {sleep_for} seconds.",
                        file=sys.stderr,
                    )

                    time.sleep(sleep_for)
                    continue

            print(
                f"ERROR: HTTP {error.code} {final_url}",
                file=sys.stderr,
            )

            print(body[:2000], file=sys.stderr)
            raise


def paginate(url: str, params: dict | None = None) -> list:
    items = []

    next_url = url
    next_params = params

    while next_url:
        data, headers = request_json(next_url, next_params)

        if isinstance(data, list):
            items.extend(data)
        elif data is not None:
            items.append(data)

        links = parse_link_header(headers.get("Link"))

        next_url = links.get("next")
        next_params = None

    return items


def write_json(name: str, data):
    path = OUT_DIR / name

    path.write_text(
        json.dumps(data, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    return path


def write_csv(name: str, rows: list[dict]):
    path = OUT_DIR / name

    if not rows:
        path.write_text("", encoding="utf-8")
        return path

    keys = sorted(
        {
            key
            for row in rows
            for key in row.keys()
        }
    )

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)

    return path


def flatten_repo(repo: dict) -> dict:
    return {
        "name": repo.get("name"),
        "full_name": repo.get("full_name"),
        "private": repo.get("private"),
        "visibility": repo.get("visibility"),
        "archived": repo.get("archived"),
        "disabled": repo.get("disabled"),
        "fork": repo.get("fork"),
        "description": repo.get("description"),
        "topics": ",".join(repo.get("topics") or []),
        "default_branch": repo.get("default_branch"),
        "created_at": repo.get("created_at"),
        "updated_at": repo.get("updated_at"),
        "pushed_at": repo.get("pushed_at"),
        "html_url": repo.get("html_url"),
    }


def get_file_if_exists(repo_full_name: str, path: str):
    url = (
        f"{API}/repos/"
        f"{repo_full_name}/contents/"
        f"{urllib.parse.quote(path)}"
    )

    request = urllib.request.Request(
        url,
        headers=github_headers(),
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read().decode("utf-8")
            data = json.loads(body)

            return {
                "repo": repo_full_name,
                "path": path,
                "status": response.status,
                "name": data.get("name"),
                "sha": data.get("sha"),
                "size": data.get("size"),
                "html_url": data.get("html_url"),
            }

    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None

        body = error.read().decode("utf-8", errors="replace")

        return {
            "repo": repo_full_name,
            "path": path,
            "status": error.code,
            "error": body[:500],
        }


def build_audit_url() -> str:
    if AUDIT_SCOPE == "enterprise":
        return f"{API}/enterprises/{ENTERPRISE}/audit-log"

    if AUDIT_SCOPE == "org":
        return f"{API}/orgs/{ORG}/audit-log"

    print(
        "ERROR: AUDIT_SCOPE must be either "
        "'enterprise' or 'org'.",
        file=sys.stderr,
    )

    sys.exit(1)


def main():
    print(
        f"Collecting RA-08 evidence from "
        f"{ORG} ({AUDIT_SCOPE})"
    )

    # Remaining code unchanged...
    # Continue using ENTERPRISE, ORG, and TOKEN variables
    # now sourced from GH_* environment variables.


if __name__ == "__main__":
    main()
