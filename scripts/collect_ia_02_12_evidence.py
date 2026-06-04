#!/usr/bin/env python3

import argparse
import csv
import datetime as dt
import json
import os
import sys
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path


GITHUB_API = "https://api.github.com"
GITHUB_GRAPHQL = "https://api.github.com/graphql"


AUDIT_SEARCH_PHRASES = {
    "saml_sso_events": "saml",
    "sso_events": "sso",
    "scim_events": "scim",
    "authentication_events": "authentication",
    "enterprise_managed_user_events": "enterprise_managed_user",
    "identity_provider_events": "identity_provider",
}


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def iso_z(value):
    return (
        value.astimezone(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def require_token():
    raw_token = os.environ.get("GH_ENTERPRISE_TOKEN") or os.environ.get("GITHUB_TOKEN")

    if raw_token is None:
        print("ERROR: Set GH_ENTERPRISE_TOKEN as a repository secret.", file=sys.stderr)
        sys.exit(1)

    token = raw_token.strip()

    if not token:
        print("ERROR: GH_ENTERPRISE_TOKEN is empty after trimming whitespace.", file=sys.stderr)
        sys.exit(1)

    invalid_chars = ["\n", "\r", "\t", " "]
    if any(char in token for char in invalid_chars):
        print(
            "ERROR: GH_ENTERPRISE_TOKEN contains whitespace or line breaks. "
            "Re-create the GitHub secret as a single-line token value.",
            file=sys.stderr,
        )
        sys.exit(1)

    return token


def github_request(method, url, token, body=None, accept="application/vnd.github+json"):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ia-02-12-evidence-collector",
    }

    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, method=method, headers=headers)

    for attempt in range(1, 6):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = response.read().decode("utf-8")
                headers_out = dict(response.headers)

                if not payload:
                    return None, headers_out

                return json.loads(payload), headers_out

        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")

            if exc.code in (403, 429) and attempt < 5:
                wait = 30 * attempt
                print(f"Rate limited or forbidden temporarily. Waiting {wait} seconds.")
                time.sleep(wait)
                continue

            print(f"ERROR: GitHub API request failed: {method} {url}", file=sys.stderr)
            print(f"HTTP {exc.code}: {detail}", file=sys.stderr)
            raise

        except urllib.error.URLError as exc:
            if attempt < 5:
                wait = 10 * attempt
                print(f"Network issue. Waiting {wait} seconds.")
                time.sleep(wait)
                continue

            raise exc


def graphql(token, query, variables):
    payload, _ = github_request(
        "POST",
        GITHUB_GRAPHQL,
        token,
        body={
            "query": query,
            "variables": variables,
        },
    )

    if payload.get("errors"):
        print(json.dumps(payload["errors"], indent=2), file=sys.stderr)
        raise RuntimeError("GraphQL query failed")

    return payload["data"]


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)

    if not rows:
        path.write_text("", encoding="utf-8")
        return

    fieldnames = sorted({key for row in rows for key in row.keys()})

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for row in rows:
            writer.writerow(row)


def flatten_json(value, prefix=""):
    output = {}

    if isinstance(value, dict):
        for key, item in value.items():
            new_prefix = f"{prefix}.{key}" if prefix else key
            output.update(flatten_json(item, new_prefix))
    elif isinstance(value, list):
        output[prefix] = json.dumps(value, sort_keys=True)
    else:
        output[prefix] = value

    return output


def normalize_enterprise_member(node):
    row = {
        "type": node.get("__typename"),
        "id": node.get("id"),
        "login": node.get("login"),
        "name": node.get("name"),
        "url": node.get("url"),
        "resource_path": node.get("resourcePath"),
        "created_at": node.get("createdAt"),
    }

    if row["url"] is None and row["resource_path"]:
        row["url"] = f"https://github.com{row['resource_path']}"

    return row


def collect_enterprise_profile(token, enterprise):
    query = """
    query EnterpriseProfile($slug: String!) {
      enterprise(slug: $slug) {
        id
        slug
        name
        description
        url
        websiteUrl
        createdAt
        location
        viewerIsAdmin
        organizations(first: 1) {
          totalCount
        }
        members(first: 1) {
          totalCount
        }
      }
    }
    """

    return graphql(token, query, {"slug": enterprise})


def collect_all_enterprise_orgs(token, enterprise):
    query = """
    query EnterpriseOrganizations($slug: String!, $cursor: String) {
      enterprise(slug: $slug) {
        organizations(first: 100, after: $cursor) {
          totalCount
          pageInfo {
            hasNextPage
            endCursor
          }
          nodes {
            id
            login
            name
            url
            viewerCanAdminister
          }
        }
      }
    }
    """

    rows = []
    cursor = None

    while True:
        data = graphql(token, query, {"slug": enterprise, "cursor": cursor})
        connection = data["enterprise"]["organizations"]

        for node in connection["nodes"]:
            rows.append(node)

        if not connection["pageInfo"]["hasNextPage"]:
            break

        cursor = connection["pageInfo"]["endCursor"]

    return rows


def collect_all_enterprise_members(token, enterprise):
    query = """
    query EnterpriseMembers($slug: String!, $cursor: String) {
      enterprise(slug: $slug) {
        members(first: 100, after: $cursor) {
          totalCount
          pageInfo {
            hasNextPage
            endCursor
          }
          nodes {
            __typename

            ... on User {
              id
              login
              name
              url
              resourcePath
              createdAt
            }

            ... on EnterpriseUserAccount {
              id
              login
              name
              resourcePath
              createdAt
            }
          }
        }
      }
    }
    """

    rows = []
    cursor = None

    while True:
        data = graphql(token, query, {"slug": enterprise, "cursor": cursor})
        connection = data["enterprise"]["members"]

        for node in connection["nodes"]:
            rows.append(normalize_enterprise_member(node))

        if not connection["pageInfo"]["hasNextPage"]:
            break

        cursor = connection["pageInfo"]["endCursor"]

    return rows


def collect_audit_log(token, enterprise, phrase, created_after):
    rows = []
    page = 1

    while True:
        query = {
            "phrase": f"{phrase} created:>={created_after}",
            "per_page": "100",
            "page": str(page),
            "include": "web",
        }

        url = (
            f"{GITHUB_API}/enterprises/"
            f"{urllib.parse.quote(enterprise)}"
            f"/audit-log?"
            f"{urllib.parse.urlencode(query)}"
        )

        payload, _ = github_request("GET", url, token)

        if not payload:
            break

        rows.extend(payload)

        if len(payload) < 100:
            break

        page += 1

    return rows


def collect_audit_stream_config(token, enterprise):
    url = f"{GITHUB_API}/enterprises/{urllib.parse.quote(enterprise)}/audit-log/streams"

    try:
        payload, _ = github_request("GET", url, token)
        return payload
    except Exception as exc:
        return {
            "collection_status": "not_collected",
            "reason": str(exc),
            "note": (
                "Audit log streaming configuration may require enterprise owner "
                "permissions or may not be enabled."
            ),
        }


def make_markdown_summary(
    path,
    enterprise,
    generated_at,
    lookback_days,
    profile,
    orgs,
    members,
    audit_counts,
):
    enterprise_data = profile.get("enterprise", {})

    lines = [
        "# IA-02(12) GitHub Enterprise Evidence Summary",
        "",
        f"Enterprise slug: `{enterprise}`",
        f"Generated at: `{generated_at}`",
        f"Lookback period: `{lookback_days}` days",
        "",
        "## Control Context",
        "",
        (
            "IA-02(12) evidence from GitHub demonstrates that the enterprise "
            "accepts federated authentication events, records SAML/SSO/SCIM-related "
            "events, and maintains an enterprise-level user and organization "
            "population. GitHub evidence should be correlated with IRS identity "
            "provider evidence showing PIV/CAC certificate-based authentication."
        ),
        "",
        "## Enterprise Profile",
        "",
        f"- Name: `{enterprise_data.get('name', '')}`",
        f"- URL: `{enterprise_data.get('url', '')}`",
        f"- Viewer is enterprise admin: `{enterprise_data.get('viewerIsAdmin', '')}`",
        f"- Enterprise-reported organization count: `{enterprise_data.get('organizations', {}).get('totalCount', '')}`",
        f"- Enterprise-reported member count: `{enterprise_data.get('members', {}).get('totalCount', '')}`",
        f"- Organizations collected: `{len(orgs)}`",
        f"- Enterprise members collected: `{len(members)}`",
        "",
        "## Audit Evidence Collected",
        "",
        "| Evidence Set | Events |",
        "|---|---:|",
    ]

    for name, count in audit_counts.items():
        lines.append(f"| {name} | {count} |")

    lines.extend(
        [
            "",
            "## Evidence Files",
            "",
            "- `enterprise_profile.json`",
            "- `enterprise_organizations.csv`",
            "- `enterprise_members.csv`",
            "- `audit_log_stream_config.json`",
            "- `audit_logs/*.json`",
            "- `audit_logs/*.csv`",
            "- `collection_metadata.json`",
            "- `IA-02-12-evidence-package.zip`",
            "",
            "## Assessor Note",
            "",
            (
                "GitHub audit data does not independently prove that a user presented "
                "a PIV credential. The authoritative proof of PIV/CAC use must come "
                "from the IRS identity provider sign-in logs. GitHub evidence supports "
                "the GitHub side of the implementation by showing enterprise federation, "
                "authentication, SSO, SCIM, and account activity."
            ),
            "",
        ]
    )

    path.write_text("\n".join(lines), encoding="utf-8")


def zip_directory(source_dir, zip_path):
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for file_path in source_dir.rglob("*"):
            if file_path == zip_path:
                continue

            if file_path.is_file():
                archive.write(file_path, file_path.relative_to(source_dir))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--enterprise", required=True)
    parser.add_argument("--lookback-days", type=int, default=30)
    parser.add_argument("--output-dir", default="evidence/IA-02-12")
    args = parser.parse_args()

    token = require_token()

    now = utc_now()
    generated_at = iso_z(now)
    created_after = iso_z(now - dt.timedelta(days=args.lookback_days))

    out_dir = Path(args.output_dir)
    audit_dir = out_dir / "audit_logs"

    out_dir.mkdir(parents=True, exist_ok=True)
    audit_dir.mkdir(parents=True, exist_ok=True)

    print(f"Collecting IA-02(12) evidence for enterprise: {args.enterprise}")
    print(f"Audit log lookback starts at: {created_after}")

    profile = collect_enterprise_profile(token, args.enterprise)
    write_json(out_dir / "enterprise_profile.json", profile)

    orgs = collect_all_enterprise_orgs(token, args.enterprise)
    write_json(out_dir / "enterprise_organizations.json", orgs)
    write_csv(out_dir / "enterprise_organizations.csv", orgs)

    members = collect_all_enterprise_members(token, args.enterprise)
    write_json(out_dir / "enterprise_members.json", members)
    write_csv(out_dir / "enterprise_members.csv", members)

    stream_config = collect_audit_stream_config(token, args.enterprise)
    write_json(out_dir / "audit_log_stream_config.json", stream_config)

    audit_counts = {}

    for evidence_name, phrase in AUDIT_SEARCH_PHRASES.items():
        print(f"Collecting audit log evidence: {evidence_name}")

        rows = collect_audit_log(
            token=token,
            enterprise=args.enterprise,
            phrase=phrase,
            created_after=created_after,
        )

        audit_counts[evidence_name] = len(rows)

        write_json(audit_dir / f"{evidence_name}.json", rows)
        write_csv(
            audit_dir / f"{evidence_name}.csv",
            [flatten_json(row) for row in rows],
        )

    metadata = {
        "control": "IA-02(12)",
        "control_name": "Identification and Authentication - Acceptance of PIV Credentials",
        "enterprise": args.enterprise,
        "generated_at": generated_at,
        "lookback_days": args.lookback_days,
        "created_after": created_after,
        "audit_search_phrases": AUDIT_SEARCH_PHRASES,
        "audit_counts": audit_counts,
        "important_note": (
            "GitHub evidence must be correlated with IRS identity provider logs "
            "to prove PIV/CAC authentication method."
        ),
    }

    write_json(out_dir / "collection_metadata.json", metadata)

    make_markdown_summary(
        path=out_dir / "IA-02-12-summary.md",
        enterprise=args.enterprise,
        generated_at=generated_at,
        lookback_days=args.lookback_days,
        profile=profile,
        orgs=orgs,
        members=members,
        audit_counts=audit_counts,
    )

    zip_directory(out_dir, out_dir / "IA-02-12-evidence-package.zip")

    print("Evidence collection complete.")
    print(f"Output directory: {out_dir}")


if __name__ == "__main__":
    main()
