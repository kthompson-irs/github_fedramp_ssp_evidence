#!/usr/bin/env python3

import json
import os
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


API_BASE = "https://api.github.com"
GRAPHQL_URL = "https://api.github.com/graphql"
API_VERSION = "2022-11-28"


def env_required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def github_request(method: str, url: str, token: str, body: dict | None = None):
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": "ia-05-01-evidence-collector",
    }

    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            response_body = response.read().decode("utf-8")

            if not response_body:
                return None, response.headers

            return json.loads(response_body), response.headers

    except urllib.error.HTTPError as error:
        response_body = error.read().decode("utf-8", errors="replace")

        return {
            "error": True,
            "status": error.code,
            "url": url,
            "body": response_body,
        }, error.headers


def paged_rest(
    path: str,
    token: str,
    query: dict | None = None,
    max_pages: int = 100,
):
    results = []
    query = query or {}
    page = 1

    while page <= max_pages:
        query_with_page = dict(query)
        query_with_page["per_page"] = 100
        query_with_page["page"] = page

        url = f"{API_BASE}{path}?{urllib.parse.urlencode(query_with_page)}"

        payload, headers = github_request(
            "GET",
            url,
            token,
        )

        if isinstance(payload, dict) and payload.get("error"):
            return {
                "error": payload,
                "partial_results": results,
            }

        if not payload:
            break

        if isinstance(payload, list):
            results.extend(payload)

            if len(payload) < 100:
                break
        else:
            return payload

        page += 1
        time.sleep(0.25)

    return results


def graphql(token: str, query: str, variables: dict):
    payload, _ = github_request(
        "POST",
        GRAPHQL_URL,
        token,
        {
            "query": query,
            "variables": variables,
        },
    )

    return payload


def get_enterprise_organizations(
    token: str,
    enterprise_slug: str,
):
    query = """
    query($slug: String!, $cursor: String) {
      enterprise(slug: $slug) {
        slug
        name
        organizations(first: 100, after: $cursor) {
          pageInfo {
            hasNextPage
            endCursor
          }
          nodes {
            login
            name
            databaseId
            url
          }
        }
      }
    }
    """

    organizations = []
    cursor = None
    enterprise_name = None

    while True:
        payload = graphql(
            token,
            query,
            {
                "slug": enterprise_slug,
                "cursor": cursor,
            },
        )

        if payload is None or payload.get("errors"):
            return {
                "error": payload,
                "organizations": organizations,
            }

        enterprise = payload["data"]["enterprise"]
        enterprise_name = enterprise.get("name")

        organizations.extend(
            enterprise["organizations"]["nodes"]
        )

        page_info = enterprise["organizations"]["pageInfo"]

        if not page_info["hasNextPage"]:
            break

        cursor = page_info["endCursor"]
        time.sleep(0.25)

    return {
        "enterprise_slug": enterprise_slug,
        "enterprise_name": enterprise_name,
        "organizations": organizations,
    }


def collect_org_evidence(
    token: str,
    org_login: str,
):
    org_profile, _ = github_request(
        "GET",
        f"{API_BASE}/orgs/{org_login}",
        token,
    )

    members_2fa_disabled = paged_rest(
        f"/orgs/{org_login}/members",
        token,
        query={
            "filter": "2fa_disabled",
            "role": "all",
        },
    )

    org_admins = paged_rest(
        f"/orgs/{org_login}/members",
        token,
        query={
            "filter": "all",
            "role": "admin",
        },
    )

    return {
        "organization": org_login,
        "org_profile": org_profile,
        "two_factor_requirement_enabled": (
            org_profile.get("two_factor_requirement_enabled")
            if isinstance(org_profile, dict)
            else None
        ),
        "members_without_2fa": members_2fa_disabled,
        "organization_admins": org_admins,
    }


def collect_enterprise_audit_evidence(
    token: str,
    enterprise_slug: str,
):
    phrases = [
        "action:org.update_default_repository_permission",
        "action:org.require_two_factor_authentication",
        "action:org.disable_two_factor_requirement",
        "action:business.update_saml_provider_settings",
        "action:business.sso_response",
        "two_factor",
        "saml",
        "sso",
        "password",
    ]

    audit_results = {}

    for phrase in phrases:
        result = paged_rest(
            f"/enterprises/{enterprise_slug}/audit-log",
            token,
            query={
                "phrase": phrase,
            },
            max_pages=3,
        )

        audit_results[phrase] = result
        time.sleep(0.5)

    return audit_results


def summarize(results: dict) -> str:
    lines = []

    lines.append("# IA-05(01) Evidence Summary")
    lines.append("")
    lines.append(f"Generated: `{results['generated_at']}`")
    lines.append(f"Enterprise: `{results['enterprise_slug']}`")
    lines.append("")
    lines.append("## Control Focus")
    lines.append("")
    lines.append(
        "IA-05(01) covers password-based authenticator management. "
        "For GitHub Enterprise Cloud / Government Cloud, direct password "
        "complexity, hashing, and compromised-password controls are inherited "
        "from GitHub as the service provider. Customer-configurable evidence "
        "primarily supports enforcement and monitoring of stronger "
        "authentication, especially 2FA/MFA and SSO-related settings."
    )
    lines.append("")
    lines.append("## Enterprise Organizations")
    lines.append("")

    orgs = results.get("organizations", [])

    lines.append(f"Organizations reviewed: `{len(orgs)}`")
    lines.append("")

    lines.append(
        "| Organization | 2FA requirement enabled | Members without 2FA | Org admins counted |"
    )
    lines.append("|---|---:|---:|---:|")

    for org in orgs:
        name = org["organization"]
        twofa = org.get("two_factor_requirement_enabled")
        no_2fa = org.get("members_without_2fa")
        admins = org.get("organization_admins")

        no_2fa_count = "ERROR"

        if isinstance(no_2fa, list):
            no_2fa_count = str(len(no_2fa))
        elif isinstance(no_2fa, dict) and "partial_results" in no_2fa:
            no_2fa_count = (
                f"ERROR; partial={len(no_2fa['partial_results'])}"
            )

        admin_count = "ERROR"

        if isinstance(admins, list):
            admin_count = str(len(admins))
        elif isinstance(admins, dict) and "partial_results" in admins:
            admin_count = (
                f"ERROR; partial={len(admins['partial_results'])}"
            )

        lines.append(
            f"| `{name}` | `{twofa}` | `{no_2fa_count}` | `{admin_count}` |"
        )

    lines.append("")
    lines.append("## IA-05(01) Implementation Evidence Statement")
    lines.append("")
    lines.append(
        "GitHub password-based authenticator composition, storage, "
        "transmission, and compromised-password protections are inherited "
        "from GitHub Enterprise Cloud / Government Cloud. This evidence "
        "package documents customer-visible controls and monitoring data, "
        "including organization-level 2FA enforcement, users without 2FA "
        "where visible to the token holder, organization administrators, "
        "and relevant enterprise audit log entries for authentication-related "
        "configuration changes."
    )

    lines.append("")
    lines.append("## Files")
    lines.append("")
    lines.append("- `ia-05-01-evidence.json`: Full machine-readable evidence")
    lines.append("- `ia-05-01-summary.md`: This summary")
    lines.append("")

    return "\n".join(lines)


def main():
    token = env_required("GH_TOKEN_FOR_AUDIT")

    enterprise_slug = os.environ.get(
        "ENTERPRISE_SLUG",
        "internal-revenue-service",
    ).strip()

    output_dir = Path(
        os.environ.get(
            "OUTPUT_DIR",
            "evidence/IA-05-01",
        )
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    generated_at = datetime.now(
        timezone.utc
    ).isoformat()

    enterprise_orgs = get_enterprise_organizations(
        token,
        enterprise_slug,
    )

    if enterprise_orgs.get("error"):
        raise SystemExit(
            "Unable to list enterprise organizations. "
            "Use an enterprise owner/admin token with sufficient "
            "enterprise/org read permissions. "
            f"Response: {json.dumps(enterprise_orgs['error'], indent=2)}"
        )

    org_results = []

    for org in enterprise_orgs["organizations"]:
        org_login = org["login"]

        print(
            f"Collecting IA-05(01) evidence for org: {org_login}",
            flush=True,
        )

        org_results.append(
            collect_org_evidence(
                token,
                org_login,
            )
        )

    print(
        "Collecting enterprise audit evidence",
        flush=True,
    )

    audit_results = collect_enterprise_audit_evidence(
        token,
        enterprise_slug,
    )

    results = {
        "control": "IA-05(01)",
        "generated_at": generated_at,
        "enterprise_slug": enterprise_slug,
        "enterprise_name": enterprise_orgs.get(
            "enterprise_name"
        ),
        "organizations": org_results,
        "enterprise_audit_log_samples": audit_results,
        "limitations": [
            (
                "GitHub.com does not expose password hashing, "
                "password blacklist, or password complexity "
                "implementation details through customer APIs."
            ),
            (
                "Password-based authenticator implementation details "
                "are service-provider inherited controls."
            ),
            (
                "Members without 2FA are only returned when the "
                "token holder has sufficient organization owner visibility."
            ),
            (
                "Enterprise audit log access requires enterprise "
                "admin privileges and appropriate token scopes."
            ),
        ],
    }

    evidence_json = output_dir / "ia-05-01-evidence.json"
    summary_md = output_dir / "ia-05-01-summary.md"

    evidence_json.write_text(
        json.dumps(
            results,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    summary_md.write_text(
        summarize(results),
        encoding="utf-8",
    )

    print(f"Wrote {evidence_json}")
    print(f"Wrote {summary_md}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
