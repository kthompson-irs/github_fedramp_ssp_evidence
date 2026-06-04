#!/usr/bin/env python3

import datetime as dt
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional


API_BASE = "https://api.github.com"
GRAPHQL_URL = "https://api.github.com/graphql"
API_VERSION = "2022-11-28"


IA05_AUDIT_ACTION_PREFIXES = [
    "oauth_authorization",
    "personal_access_token",
    "fine_grained_personal_access_token",
    "ssh_key",
    "public_key",
    "gpg_key",
    "webauthn_credential",
    "two_factor_authentication",
    "saml_identity",
    "org_credential_authorization",
    "integration_installation",
    "github_app_authorization",
    "repo.add_member",
    "repo.remove_member",
    "org.add_member",
    "org.remove_member",
    "org.update_member",
    "enterprise.add_member",
    "enterprise.remove_member",
]


class GitHubClient:
    def __init__(self, token: str) -> None:
        self.token = token.strip()

        if not self.token:
            raise ValueError("GitHub token is empty.")

        if "\n" in self.token or "\r" in self.token:
            raise ValueError(
                "GitHub token contains newline characters. "
                "Re-save the secret as a single-line token."
            )

    def request_json(
        self,
        method: str,
        url: str,
        body: Optional[Dict[str, Any]] = None,
        accept: str = "application/vnd.github+json",
    ) -> Any:
        data = None

        if body is not None:
            data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", accept)
        req.add_header("X-GitHub-Api-Version", API_VERSION)
        req.add_header("User-Agent", "ia05-evidence-collector")

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read().decode("utf-8")
                if not raw:
                    return None
                return json.loads(raw)

        except urllib.error.HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"{method} {url} failed: HTTP {exc.code}: {details}"
            ) from exc

    def get_paginated(
        self,
        url: str,
        max_pages: int = 50,
        tolerate_http_errors: bool = False,
    ) -> List[Any]:
        results: List[Any] = []
        next_url = url
        pages = 0

        while next_url and pages < max_pages:
            pages += 1

            req = urllib.request.Request(next_url, method="GET")
            req.add_header("Authorization", f"Bearer {self.token}")
            req.add_header("Accept", "application/vnd.github+json")
            req.add_header("X-GitHub-Api-Version", API_VERSION)
            req.add_header("User-Agent", "ia05-evidence-collector")

            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    payload = json.loads(resp.read().decode("utf-8") or "[]")

                    if isinstance(payload, list):
                        results.extend(payload)
                    else:
                        results.append(payload)

                    link = resp.headers.get("Link", "")
                    next_url = self._parse_next_link(link)

            except urllib.error.HTTPError as exc:
                details = exc.read().decode("utf-8", errors="replace")

                if tolerate_http_errors:
                    results.append(
                        {
                            "status": "not_collected",
                            "url": next_url,
                            "http_status": exc.code,
                            "reason": details,
                        }
                    )
                    return results

                raise RuntimeError(
                    f"GET {next_url} failed: HTTP {exc.code}: {details}"
                ) from exc

            time.sleep(0.25)

        return results

    @staticmethod
    def _parse_next_link(link_header: str) -> Optional[str]:
        if not link_header:
            return None

        for part in link_header.split(","):
            section = part.strip().split(";")
            if len(section) < 2:
                continue

            url_part = section[0].strip()
            rel_part = section[1].strip()

            if rel_part == 'rel="next"':
                return url_part[1:-1]

        return None

    def graphql(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        payload = self.request_json(
            "POST",
            GRAPHQL_URL,
            {
                "query": query,
                "variables": variables,
            },
            accept="application/vnd.github+json",
        )

        if payload.get("errors"):
            raise RuntimeError(json.dumps(payload["errors"], indent=2))

        return payload["data"]


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def collect_enterprise_organizations(
    client: GitHubClient,
    enterprise: str,
) -> List[Dict[str, Any]]:
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
            viewerCanAdminister
          }
        }
      }
    }
    """

    orgs: List[Dict[str, Any]] = []
    cursor = None

    while True:
        data = client.graphql(query, {"slug": enterprise, "cursor": cursor})
        enterprise_data = data.get("enterprise")

        if not enterprise_data:
            raise RuntimeError(f"Enterprise not found or inaccessible: {enterprise}")

        org_page = enterprise_data["organizations"]
        orgs.extend(org_page["nodes"])

        if not org_page["pageInfo"]["hasNextPage"]:
            break

        cursor = org_page["pageInfo"]["endCursor"]

    return orgs


def collect_enterprise_audit_log(
    client: GitHubClient,
    enterprise: str,
    lookback_days: int,
) -> Dict[str, Any]:
    since_date = (utc_now() - dt.timedelta(days=lookback_days)).date().isoformat()

    collected_events: List[Dict[str, Any]] = []
    query_results: List[Dict[str, Any]] = []

    for action_prefix in IA05_AUDIT_ACTION_PREFIXES:
        phrase = f"action:{action_prefix} created:>={since_date}"

        encoded = urllib.parse.urlencode(
            {
                "phrase": phrase,
                "include": "all",
                "per_page": "100",
            }
        )

        url = f"{API_BASE}/enterprises/{enterprise}/audit-log?{encoded}"

        try:
            events = client.get_paginated(url, max_pages=20)
            collected_events.extend(events)

            query_results.append(
                {
                    "action_prefix": action_prefix,
                    "phrase": phrase,
                    "status": "collected",
                    "event_count": len(events),
                }
            )

        except Exception as exc:
            query_results.append(
                {
                    "action_prefix": action_prefix,
                    "phrase": phrase,
                    "status": "not_collected",
                    "reason": str(exc),
                }
            )

    deduped_events: Dict[str, Dict[str, Any]] = {}

    for event in collected_events:
        event_id = (
            event.get("_document_id")
            or event.get("@timestamp")
            or event.get("created_at")
            or json.dumps(event, sort_keys=True)
        )
        deduped_events[str(event_id)] = event

    return {
        "lookback_days": lookback_days,
        "since_date": since_date,
        "query_results": query_results,
        "events": list(deduped_events.values()),
    }


def collect_org_saml_credential_authorizations(
    client: GitHubClient,
    org: str,
) -> Dict[str, Any]:
    url = f"{API_BASE}/orgs/{org}/credential-authorizations?per_page=100"

    try:
        records = client.get_paginated(url, max_pages=50)

        return {
            "org": org,
            "status": "collected",
            "credential_authorizations": records,
        }

    except Exception as exc:
        return {
            "org": org,
            "status": "not_collected",
            "reason": str(exc),
        }


def collect_org_pat_requests(
    client: GitHubClient,
    org: str,
) -> Dict[str, Any]:
    url = f"{API_BASE}/orgs/{org}/personal-access-token-requests?per_page=100"

    try:
        records = client.get_paginated(url, max_pages=50)

        return {
            "org": org,
            "status": "collected",
            "personal_access_token_requests": records,
        }

    except Exception as exc:
        return {
            "org": org,
            "status": "not_collected",
            "reason": str(exc),
        }


def collect_org_fine_grained_pats(
    client: GitHubClient,
    org: str,
) -> Dict[str, Any]:
    url = f"{API_BASE}/orgs/{org}/personal-access-tokens?per_page=100"

    try:
        records = client.get_paginated(url, max_pages=50)

        return {
            "org": org,
            "status": "collected",
            "fine_grained_personal_access_tokens": records,
        }

    except Exception as exc:
        return {
            "org": org,
            "status": "not_collected",
            "reason": str(exc),
        }


def build_markdown_summary(
    enterprise: str,
    lookback_days: int,
    orgs: List[Dict[str, Any]],
    audit_log: Dict[str, Any],
    saml_authz: List[Dict[str, Any]],
    pat_requests: List[Dict[str, Any]],
    fine_grained_pats: List[Dict[str, Any]],
) -> str:
    generated = utc_now().isoformat()

    audit_events = audit_log.get("events", [])
    audit_query_results = audit_log.get("query_results", [])

    collected_audit_queries = sum(
        1 for item in audit_query_results if item["status"] == "collected"
    )

    collected_saml = sum(1 for item in saml_authz if item["status"] == "collected")
    collected_pat_requests = sum(
        1 for item in pat_requests if item["status"] == "collected"
    )
    collected_fine_grained_pats = sum(
        1 for item in fine_grained_pats if item["status"] == "collected"
    )

    lines = [
        "# IA-05 Authenticator Management Evidence",
        "",
        f"Enterprise: `{enterprise}`",
        f"Generated UTC: `{generated}`",
        f"Audit log lookback: `{lookback_days}` days",
        f"Audit log since date: `{audit_log.get('since_date', 'unknown')}`",
        "",
        "## Collection Summary",
        "",
        "| Evidence Area | Result | IA-05 Relevance |",
        "|---|---:|---|",
        f"| Enterprise organizations discovered | {len(orgs)} | Scope of GitHub Enterprise Cloud organizations |",
        f"| IA-05 audit-log queries completed | {collected_audit_queries}/{len(audit_query_results)} | Authenticator-related audit evidence collection coverage |",
        f"| IA-05-related enterprise audit events | {len(audit_events)} | Authenticator issuance, change, revocation, SSO, token, SSH key, and MFA activity |",
        f"| Organizations with SAML credential authorization evidence collected | {collected_saml}/{len(orgs)} | Authorized PAT and SSH-key usage with SAML SSO |",
        f"| Organizations with PAT request evidence collected | {collected_pat_requests}/{len(orgs)} | PAT approval and denial workflow evidence |",
        f"| Organizations with fine-grained PAT inventory evidence collected | {collected_fine_grained_pats}/{len(orgs)} | Token inventory, scope, owner, and lifecycle review evidence |",
        "",
        "## IA-05 Audit Query Results",
        "",
        "| Action Prefix | Status | Event Count / Reason |",
        "|---|---|---|",
    ]

    for item in audit_query_results:
        result = (
            str(item.get("event_count", 0))
            if item["status"] == "collected"
            else item.get("reason", "not collected").replace("\n", " ")
        )

        lines.append(
            f"| `{item['action_prefix']}` | `{item['status']}` | {result} |"
        )

    lines.extend(
        [
            "",
            "## IA-05 Control Mapping",
            "",
            "| IA-05 Evidence Need | GitHub Evidence Collected |",
            "|---|---|",
            "| Authenticator issuance and lifecycle | Enterprise audit log events for SSO, PAT, SSH key, GitHub App, OAuth, and membership activity |",
            "| Authenticator revocation | Audit events showing removal, deletion, expiration, or authorization revocation |",
            "| Non-password authenticators | SAML credential authorizations, SSH keys, PATs, fine-grained PATs, GitHub App authorizations |",
            "| Least privilege and token review | Fine-grained PAT inventory and PAT access-request records |",
            "| Compromise response support | Audit events showing credential changes, revocations, and administrative actions |",
            "| Continuous monitoring | Timestamped enterprise-level and organization-level evidence artifacts |",
            "",
            "## Output Files",
            "",
            "- `enterprise-organizations.json`",
            "- `enterprise-audit-log-ia05.json`",
            "- `org-saml-credential-authorizations.json`",
            "- `org-personal-access-token-requests.json`",
            "- `org-fine-grained-personal-access-tokens.json`",
            "- `ia05-summary.md`",
            "",
            "## Notes",
            "",
            "- GitHub audit-log phrase filters are collected one action prefix at a time to avoid invalid compound query syntax.",
            "- Some organization evidence may report `not_collected` if the token lacks required enterprise or organization permissions.",
            "- The token should belong to an enterprise administrator or GitHub App with equivalent approved permissions.",
            "- Classic PATs for enterprise audit-log access require `read:audit_log`.",
            "- This collection does not retrieve secret values, passwords, private keys, or token plaintext.",
            "- Identity-provider password policy, MFA policy, and FIPS/FedRAMP boundary evidence should be collected from the IdP and SSP package separately.",
            "",
        ]
    )

    return "\n".join(lines)


def get_token_from_environment() -> str:
    token = (
        os.environ.get("GH_ENTERPRISE_ADMIN_TOKEN")
        or os.environ.get("GITHUB_TOKEN")
        or ""
    ).strip()

    if not token:
        raise ValueError(
            "GitHub token is required. Set GH_ENTERPRISE_ADMIN_TOKEN or GITHUB_TOKEN."
        )

    return token


def main() -> int:
    try:
        token = get_token_from_environment()
        enterprise = os.environ.get("GITHUB_ENTERPRISE", "internal-revenue-service").strip()
        output_dir = Path(os.environ.get("OUTPUT_DIR", "ia05-evidence"))
        lookback_days = int(os.environ.get("IA05_LOOKBACK_DAYS", "90"))

        output_dir.mkdir(parents=True, exist_ok=True)

        client = GitHubClient(token)

        orgs = collect_enterprise_organizations(client, enterprise)
        write_json(output_dir / "enterprise-organizations.json", orgs)

        audit_log = collect_enterprise_audit_log(client, enterprise, lookback_days)
        write_json(output_dir / "enterprise-audit-log-ia05.json", audit_log)

        saml_authz = []
        pat_requests = []
        fine_grained_pats = []

        for org in orgs:
            login = org["login"]

            saml_authz.append(
                collect_org_saml_credential_authorizations(client, login)
            )

            pat_requests.append(
                collect_org_pat_requests(client, login)
            )

            fine_grained_pats.append(
                collect_org_fine_grained_pats(client, login)
            )

        write_json(
            output_dir / "org-saml-credential-authorizations.json",
            saml_authz,
        )

        write_json(
            output_dir / "org-personal-access-token-requests.json",
            pat_requests,
        )

        write_json(
            output_dir / "org-fine-grained-personal-access-tokens.json",
            fine_grained_pats,
        )

        summary = build_markdown_summary(
            enterprise=enterprise,
            lookback_days=lookback_days,
            orgs=orgs,
            audit_log=audit_log,
            saml_authz=saml_authz,
            pat_requests=pat_requests,
            fine_grained_pats=fine_grained_pats,
        )

        (output_dir / "ia05-summary.md").write_text(summary, encoding="utf-8")

        print(f"IA-05 evidence collection complete. Output: {output_dir}")
        return 0

    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
