#!/usr/bin/env python3
"""Enterprise-level RA-03 evidence collector for GitHub.com Enterprise Cloud.

This script inventories repositories across one or more GitHub organizations,
collects repository security and workflow signals, and produces an enterprise
summary plus per-repository detail files.

It is designed to support risk assessment evidence collection for NIST RA-03.
It does not certify compliance by itself.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


API_DEFAULT = "https://api.github.com"
API_VERSION = "2022-11-28"
PER_PAGE = 100
MAX_WORKERS = 6
TEXT_FILE_NAMES = {
    "CODEOWNERS",
    "SECURITY.md",
    "dependabot.yml",
    "dependabot.yaml",
}

SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}

DANGEROUS_RUN_PATTERNS = [
    (re.compile(r"curl\s+[^\n|]+\|\s*(sh|bash)"), "Pipe-to-shell command detected."),
    (re.compile(r"wget\s+[^\n|]+\|\s*(sh|bash)"), "Pipe-to-shell command detected."),
    (re.compile(r"sudo\s+"), "Use of sudo in workflow step."),
]

ACTION_USE_RE = re.compile(r"^\s*uses:\s*([^\s#]+)\s*$", re.MULTILINE)
WRITE_PERMISSION_RE = re.compile(r"permissions:\s*\n(?P<body>(?:\s+[A-Za-z0-9_-]+:\s*[A-Za-z_-]+\s*\n?)+)", re.MULTILINE)
WRITE_ALL_RE = re.compile(r"permissions:\s*\bwrite-all\b")
SHA_RE = re.compile(r"@[0-9a-fA-F]{40}$")
LOCAL_ACTION_RE = re.compile(r"^\./")


@dataclasses.dataclass
class Finding:
    id: str
    title: str
    severity: str
    scope: str
    details: str
    recommendation: str


@dataclasses.dataclass
class RepoResult:
    org: str
    name: str
    full_name: str
    archived: bool
    disabled: bool
    visibility: str
    default_branch: str
    score: int
    status: str
    findings: List[Finding]
    evidence: Dict[str, object]


@dataclasses.dataclass
class Report:
    repository: str
    ref: str
    sha: str
    generated_at_utc: str
    score: int
    status: str
    org_count: int
    repo_count: int
    findings: List[Finding]
    repositories: List[RepoResult]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def short_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


def split_csv(value: str) -> List[str]:
    items = [part.strip() for part in value.split(",")]
    return [item for item in items if item]


def env(name: str, default: str = "") -> str:
    return os.getenv(name, default)


class GitHubClient:
    def __init__(self, api_base: str, token: str, timeout: int = 30):
        self.api_base = api_base.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _request(self, method: str, path: str, params: Optional[Dict[str, str]] = None) -> Tuple[dict, Dict[str, str]]:
        url = f"{self.api_base}{path}"
        if params:
            query = "&".join(f"{quote(str(k))}={quote(str(v))}" for k, v in params.items())
            url = f"{url}?{query}"

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "enterprise-ra03-assessment",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        req = Request(url, method=method, headers=headers)
        with urlopen(req, timeout=self.timeout) as resp:
            payload = resp.read().decode("utf-8", errors="replace")
            data = json.loads(payload) if payload else {}
            return data, dict(resp.headers.items())

    def get_json(self, path: str, params: Optional[Dict[str, str]] = None, retries: int = 4) -> dict:
        delay = 1.0
        for attempt in range(retries + 1):
            try:
                data, _ = self._request("GET", path, params=params)
                return data
            except HTTPError as exc:
                # Respect GitHub rate limits and temporary server-side failures.
                if exc.code in {429, 500, 502, 503, 504} and attempt < retries:
                    time.sleep(delay)
                    delay *= 2
                    continue
                body = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else ""
                raise RuntimeError(f"GET {path} failed with HTTP {exc.code}: {body[:300]}") from exc
            except URLError as exc:
                if attempt < retries:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise RuntimeError(f"GET {path} failed: {exc}") from exc
        raise RuntimeError(f"GET {path} failed after {retries + 1} attempts")


def paginate(client: GitHubClient, path: str, params: Optional[Dict[str, str]] = None) -> List[dict]:
    params = dict(params or {})
    params.setdefault("per_page", str(PER_PAGE))
    results: List[dict] = []
    page = 1
    while True:
        params["page"] = str(page)
        chunk = client.get_json(path, params=params)
        if not isinstance(chunk, list):
            raise RuntimeError(f"Expected list response from {path}, got {type(chunk).__name__}")
        results.extend(chunk)
        if len(chunk) < PER_PAGE:
            break
        page += 1
    return results


def discover_repo_files(repo_root: Path) -> List[Path]:
    files: List[Path] = []
    for name in TEXT_FILE_NAMES:
        files.extend(sorted(repo_root.rglob(name)))
    for pattern in (".github/workflows/*.yml", ".github/workflows/*.yaml"):
        files.extend(sorted(repo_root.glob(pattern)))
    seen = set()
    out = []
    for path in files:
        if path in seen:
            continue
        seen.add(path)
        out.append(path)
    return out


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def classify_permissions(text: str) -> Optional[str]:
    if WRITE_ALL_RE.search(text):
        return "write-all"
    m = WRITE_PERMISSION_RE.search(text)
    if not m:
        return None
    body = m.group("body")
    write_scopes: List[str] = []
    for line in body.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        scope, value = [part.strip() for part in line.split(":", 1)]
        if value in {"write", "read-all", "write-all"}:
            write_scopes.append(f"{scope}={value}")
    return ", ".join(write_scopes) if write_scopes else None


def is_pinned_action(value: str) -> bool:
    value = value.strip()
    return bool(LOCAL_ACTION_RE.match(value) or SHA_RE.search(value))


def analyze_workflow_text(scope: str, text: str) -> List[Finding]:
    findings: List[Finding] = []

    if "pull_request_target" in text:
        findings.append(
            Finding(
                id=f"{short_hash((scope + 'prtarget').encode())}",
                title="Workflow uses pull_request_target",
                severity="medium",
                scope=scope,
                details="pull_request_target runs with elevated token context and should be used carefully.",
                recommendation="Prefer pull_request when possible; if pull_request_target is required, do not execute untrusted PR code.",
            )
        )

    perms = classify_permissions(text)
    if perms:
        severity = "high" if "write-all" in perms else "medium"
        findings.append(
            Finding(
                id=f"{short_hash((scope + perms).encode())}",
                title="Workflow grants write permissions",
                severity=severity,
                scope=scope,
                details=f"Detected broad permissions: {perms}.",
                recommendation="Reduce workflow permissions to the minimum required scope.",
            )
        )

    for match in ACTION_USE_RE.finditer(text):
        uses = match.group(1).strip()
        if uses.startswith("./") or uses.startswith("docker://"):
            continue
        if not is_pinned_action(uses):
            findings.append(
                Finding(
                    id=f"{short_hash((scope + uses).encode())}",
                    title="Action is not pinned to a commit SHA",
                    severity="medium",
                    scope=scope,
                    details=f"Action reference '{uses}' is not pinned to a 40-character commit SHA.",
                    recommendation="Pin third-party actions to a full commit SHA and review pinned versions regularly.",
                )
            )

    for pattern, message in DANGEROUS_RUN_PATTERNS:
        for m in pattern.finditer(text):
            snippet = text[max(0, m.start() - 40): m.end() + 40].replace("\n", " ")
            findings.append(
                Finding(
                    id=f"{short_hash((scope + snippet).encode())}",
                    title=message,
                    severity="high" if "Pipe-to-shell" in message else "medium",
                    scope=scope,
                    details=f"Potentially risky command snippet: {snippet.strip()}",
                    recommendation="Replace pipe-to-shell installs with checked-in scripts or vendor-supplied actions.",
                )
            )
            break

    if "schedule:" in text:
        findings.append(
            Finding(
                id=f"{short_hash((scope + 'schedule').encode())}",
                title="Scheduled execution configured",
                severity="info",
                scope=scope,
                details="Workflow contains a schedule trigger.",
                recommendation="Use scheduled runs to refresh the assessment periodically.",
            )
        )

    if "codeql" in text.lower():
        findings.append(
            Finding(
                id=f"{short_hash((scope + 'codeql').encode())}",
                title="Code scanning workflow detected",
                severity="info",
                scope=scope,
                details="A CodeQL or code-scanning workflow appears to be present.",
                recommendation="Keep code scanning enabled on push and schedule so vulnerabilities are reviewed continuously.",
            )
        )

    return findings


def github_list_repos(client: GitHubClient, org: str) -> List[dict]:
    return paginate(client, f"/orgs/{quote(org)}/repos", {"type": "all", "sort": "updated", "direction": "desc"})


def github_get_repo(client: GitHubClient, full_name: str) -> dict:
    owner, repo = full_name.split("/", 1)
    return client.get_json(f"/repos/{quote(owner)}/{quote(repo)}")


def github_list_workflows(client: GitHubClient, full_name: str) -> List[dict]:
    owner, repo = full_name.split("/", 1)
    try:
        data = client.get_json(f"/repos/{quote(owner)}/{quote(repo)}/actions/workflows", {"per_page": str(PER_PAGE)})
        return data.get("workflows", []) if isinstance(data, dict) else []
    except RuntimeError:
        return []


def github_get_content(client: GitHubClient, full_name: str, path: str, ref: Optional[str] = None) -> Optional[str]:
    owner, repo = full_name.split("/", 1)
    params = {"ref": ref} if ref else None
    try:
        data = client.get_json(f"/repos/{quote(owner)}/{quote(repo)}/contents/{path}", params=params)
    except RuntimeError:
        return None
    if isinstance(data, dict) and data.get("encoding") == "base64" and "content" in data:
        import base64

        raw = data["content"].replace("\n", "")
        return base64.b64decode(raw).decode("utf-8", errors="replace")
    return None


def assess_repo(client: GitHubClient, repo: dict, repo_root: Path) -> RepoResult:
    full_name = repo["full_name"]
    org, name = full_name.split("/", 1)
    visibility = repo.get("visibility", "unknown")
    archived = bool(repo.get("archived", False))
    disabled = bool(repo.get("disabled", False))
    default_branch = repo.get("default_branch") or "main"

    findings: List[Finding] = []
    evidence: Dict[str, object] = {
        "repo_api": {
            "full_name": full_name,
            "visibility": visibility,
            "archived": archived,
            "disabled": disabled,
            "default_branch": default_branch,
        }
    }

    try:
        detailed = github_get_repo(client, full_name)
        evidence["repo_details"] = {
            "has_security_and_analysis": bool(detailed.get("security_and_analysis")),
            "security_and_analysis": detailed.get("security_and_analysis", {}),
        }
        saa = detailed.get("security_and_analysis") or {}
        if saa:
            for feature_name in ("advanced_security", "secret_scanning", "secret_scanning_push_protection", "dependabot_security_updates"):
                feature = saa.get(feature_name)
                if isinstance(feature, dict):
                    state = feature.get("status") or feature.get("state") or "unknown"
                    if state not in {"enabled", "on"}:
                        findings.append(
                            Finding(
                                id=f"{short_hash((full_name + feature_name).encode())}",
                                title=f"Repository security feature not enabled: {feature_name}",
                                severity="medium",
                                scope=full_name,
                                details=f"{feature_name} status appears to be {state}.",
                                recommendation="Enable repository security features where the subscription and policy allow it.",
                            )
                        )
    except RuntimeError as exc:
        evidence["repo_details_error"] = str(exc)

    if archived:
        findings.append(
            Finding(
                id=f"{short_hash((full_name + 'archived').encode())}",
                title="Repository is archived",
                severity="info",
                scope=full_name,
                details="Archived repositories are lower-risk from a change perspective but still need inventory visibility.",
                recommendation="Keep archived repositories in the enterprise inventory and review them during periodic assessments.",
            )
        )

    if disabled:
        findings.append(
            Finding(
                id=f"{short_hash((full_name + 'disabled').encode())}",
                title="Repository is disabled",
                severity="low",
                scope=full_name,
                details="Disabled repositories may indicate inactive or paused assets that still need risk review.",
                recommendation="Confirm whether the repository should remain disabled or be retired.",
            )
        )

    workflow_texts: List[Tuple[str, str]] = []
    try:
        workflows = github_list_workflows(client, full_name)
        evidence["workflow_inventory"] = workflows
        for wf in workflows:
            wf_path = wf.get("path")
            if not wf_path:
                continue
            text = github_get_content(client, full_name, wf_path.lstrip("/"), ref=default_branch)
            if text:
                workflow_texts.append((wf_path, text))
    except RuntimeError as exc:
        evidence["workflow_inventory_error"] = str(exc)

    local_repo_dir = repo_root / name
    if local_repo_dir.exists() and local_repo_dir.is_dir():
        local_files = discover_repo_files(local_repo_dir)
        evidence["local_files_scanned"] = [str(p.relative_to(local_repo_dir)) for p in local_files]
        for path in local_files:
            text = read_text(path)
            workflow_texts.append((str(path.relative_to(local_repo_dir)), text))

    for scope, text in workflow_texts:
        findings.extend(analyze_workflow_text(f"{full_name}:{scope}", text))

    if local_repo_dir.exists() and local_repo_dir.is_dir():
        names = {p.name for p in discover_repo_files(local_repo_dir)}
        if "CODEOWNERS" not in names:
            findings.append(
                Finding(
                    id=f"{short_hash((full_name + 'codeowners').encode())}",
                    title="CODEOWNERS file not found",
                    severity="low",
                    scope=full_name,
                    details="No CODEOWNERS file was found in the repository checkout.",
                    recommendation="Add CODEOWNERS so the right reviewers are included in risk-relevant changes.",
                )
            )
        if not any(n.lower() in {"dependabot.yml", "dependabot.yaml"} for n in names):
            findings.append(
                Finding(
                    id=f"{short_hash((full_name + 'dependabot').encode())}",
                    title="Dependabot configuration not found",
                    severity="low",
                    scope=full_name,
                    details="No Dependabot configuration file was found in the repository checkout.",
                    recommendation="Add Dependabot to keep dependency risk visible and reviewable.",
                )
            )
        if not any("security" in n.lower() and n.endswith(".md") for n in names):
            findings.append(
                Finding(
                    id=f"{short_hash((full_name + 'securitymd').encode())}",
                    title="Security policy file not found",
                    severity="low",
                    scope=full_name,
                    details="No SECURITY.md file was found in the repository checkout.",
                    recommendation="Add a security policy to document vulnerability reporting and triage expectations.",
                )
            )

    unique: List[Finding] = []
    seen = set()
    for f in findings:
        key = (f.title, f.scope, f.details)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    findings = unique

    score = 100
    for f in findings:
        score -= SEVERITY_WEIGHTS.get(f.severity, 0)
    score = max(0, min(100, score))

    if score >= 90:
        status = "pass"
    elif score >= 70:
        status = "attention"
    else:
        status = "fail"

    return RepoResult(
        org=org,
        name=name,
        full_name=full_name,
        archived=archived,
        disabled=disabled,
        visibility=visibility,
        default_branch=default_branch,
        score=score,
        status=status,
        findings=findings,
        evidence=evidence,
    )


def aggregate_report(repo_results: List[RepoResult], repository: str, ref: str, sha: str) -> Report:
    findings: List[Finding] = []
    for repo in repo_results:
        findings.extend(repo.findings)

    if not repo_results:
        score = 0
        status = "fail"
    else:
        score = round(sum(r.score for r in repo_results) / len(repo_results))
        status = "pass" if score >= 90 else ("attention" if score >= 70 else "fail")

    return Report(
        repository=repository,
        ref=ref,
        sha=sha,
        generated_at_utc=utc_now(),
        score=score,
        status=status,
        org_count=len({r.org for r in repo_results}),
        repo_count=len(repo_results),
        findings=findings,
        repositories=repo_results,
    )


def render_markdown(report: Report) -> str:
    lines = [
        "# Enterprise RA-03 Risk Assessment",
        "",
        f"Repository: `{report.repository}`",
        f"Ref: `{report.ref}`",
        f"Commit: `{report.sha}`",
        f"Generated (UTC): `{report.generated_at_utc}`",
        f"Organizations scanned: **{report.org_count}**",
        f"Repositories scanned: **{report.repo_count}**",
        f"Enterprise score: **{report.score}/100**",
        f"Status: **{report.status.upper()}**",
        "",
        "## Top Findings",
    ]

    if not report.findings:
        lines.append("No findings.")
    else:
        for finding in report.findings[:200]:
            lines.extend([
                f"- **[{finding.severity.upper()}] {finding.title}** ({finding.scope})",
                f"  - {finding.details}",
                f"  - Recommendation: {finding.recommendation}",
            ])
        if len(report.findings) > 200:
            lines.append(f"- ... {len(report.findings) - 200} more findings omitted from summary")

    lines.extend(["", "## Repository Summary"])
    for repo in report.repositories:
        lines.append(f"- `{repo.full_name}` — score {repo.score}/100 — {repo.status.upper()} — {repo.visibility}")

    lines.extend(["", "## Notes", "This report is a control-support artifact for enterprise RA-03 evidence collection."])
    return "\n".join(lines) + "\n"


def write_outputs(report: Report, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    repos_dir = output_dir / "repos"
    repos_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / "enterprise-ra03-report.json"
    md_path = output_dir / "enterprise-ra03-report.md"

    payload = {
        "repository": report.repository,
        "ref": report.ref,
        "sha": report.sha,
        "generated_at_utc": report.generated_at_utc,
        "score": report.score,
        "status": report.status,
        "org_count": report.org_count,
        "repo_count": report.repo_count,
        "findings": [dataclasses.asdict(f) for f in report.findings],
        "repositories": [dataclasses.asdict(r) for r in report.repositories],
    }

    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")

    for repo in report.repositories:
        repo_file = repos_dir / f"{repo.full_name.replace('/', '__')}.json"
        repo_file.write_text(json.dumps(dataclasses.asdict(repo), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    step_summary = os.getenv("GITHUB_STEP_SUMMARY")
    if step_summary:
        Path(step_summary).write_text(render_markdown(report), encoding="utf-8")

    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    print(f"Score: {report.score} Status: {report.status}")


def build_client() -> GitHubClient:
    api_base = env("GH_API_URL", API_DEFAULT)
    token = env("GH_TOKEN", env("GITHUB_TOKEN", ""))
    if not token:
        raise SystemExit("GH_TOKEN is required. Provide a fine-grained PAT or GitHub App token with read access.")
    return GitHubClient(api_base=api_base, token=token)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run an enterprise RA-03 assessment across organizations.")
    parser.add_argument("--orgs", required=True, help="Comma-separated list of organizations to scan.")
    parser.add_argument("--repo-root", default=".", help="Local repository root for optional fallback scanning.")
    parser.add_argument("--output-dir", default="enterprise-ra03-artifacts", help="Directory for generated artifacts.")
    parser.add_argument("--fail-below", type=int, default=75, help="Exit non-zero when enterprise score is below this threshold.")
    args = parser.parse_args(argv)

    client = build_client()
    orgs = split_csv(args.orgs)
    if not orgs:
        raise SystemExit("At least one organization is required.")

    repo_results: List[RepoResult] = []
    repo_root = Path(args.repo_root).resolve()

    all_repos: List[dict] = []
    for org in orgs:
        all_repos.extend(github_list_repos(client, org))

    seen_full_names = set()
    unique_repos: List[dict] = []
    for repo in all_repos:
        full_name = repo.get("full_name")
        if not full_name or full_name in seen_full_names:
            continue
        seen_full_names.add(full_name)
        unique_repos.append(repo)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(assess_repo, client, repo, repo_root) for repo in unique_repos]
        for future in as_completed(futures):
            repo_results.append(future.result())

    repo_results.sort(key=lambda r: r.full_name.lower())

    report = aggregate_report(
        repo_results=repo_results,
        repository=env("GH_REPOSITORY", env("GITHUB_REPOSITORY", "enterprise-ra03-assessment")),
        ref=env("GH_REF_NAME", env("GITHUB_REF_NAME", env("GITHUB_REF", "local"))),
        sha=env("GH_SHA", env("GITHUB_SHA", "local")),
    )

    write_outputs(report, Path(args.output_dir).resolve())

    if report.score < args.fail_below:
        print(
            f"Enterprise risk score {report.score} is below threshold {args.fail_below}; failing the job to force review.",
            file=sys.stderr,
        )
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
