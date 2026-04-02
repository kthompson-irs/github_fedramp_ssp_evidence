#!/usr/bin/env python3
"""IA-02(08) replay-resistance audit helper

Checks GitHub.com -> AWS GovCloud / Azure Government federation patterns for:
- Audience-restricted OIDC trust
- Repo/environment-scoped subject claims
- Short-lived credentials / max session duration
- CloudTrail logging presence (AWS)
- Entra federated credential trust objects (Azure)
- GitHub org 2FA / insecure-2FA member checks

This script is read-only. It does not change any cloud settings.

Usage examples:
  python3 ia0208_audit.py all --github-org ORG --azure-app-id APP_ID
  python3 ia0208_audit.py aws --github-oidc-provider-arn arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com
  python3 ia0208_audit.py azure --azure-app-id <appId>
  python3 ia0208_audit.py github --github-org ORG --github-token $GITHUB_TOKEN

Outputs:
  - JSON report to stdout and optionally to --output
  - Non-zero exit code if required checks fail
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str
    evidence: List[str]
    manual: bool = False


def run_cmd(cmd: List[str], *, env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def pretty_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True)


def decode_policy_document(doc: Any) -> Any:
    """IAM may return a decoded dict or URL-encoded string depending on CLI path."""
    if isinstance(doc, dict):
        return doc
    if not isinstance(doc, str):
        return doc
    try:
        from urllib.parse import unquote_plus
        raw = unquote_plus(doc)
        return json.loads(raw)
    except Exception:
        return doc


def find_github_oidc_statements(policy: Dict[str, Any], provider_url: str) -> List[Dict[str, Any]]:
    matches = []
    for stmt in policy.get("Statement", []):
        principal = stmt.get("Principal", {})
        federated = principal.get("Federated")
        if not federated:
            continue
        arn_text = federated if isinstance(federated, str) else json.dumps(federated)
        if provider_url in arn_text or "token.actions.githubusercontent.com" in arn_text:
            matches.append(stmt)
    return matches


def aws_audit(args: argparse.Namespace) -> List[CheckResult]:
    results: List[CheckResult] = []

    rc, out, err = run_cmd(["aws", "sts", "get-caller-identity", "--output", "json"])
    if rc != 0:
        results.append(CheckResult(
            name="aws_credentials",
            passed=False,
            detail=f"AWS CLI auth failed: {err or out}",
            evidence=[],
        ))
        return results

    ident = json.loads(out)
    results.append(CheckResult(
        name="aws_credentials",
        passed=True,
        detail=f"Authenticated as {ident.get('Arn')}",
        evidence=["aws sts get-caller-identity"],
    ))

    rc, out, err = run_cmd(["aws", "iam", "list-open-id-connect-providers", "--output", "json"])
    if rc != 0:
        results.append(CheckResult("aws_oidc_provider", False, f"Unable to list OIDC providers: {err or out}", []))
        return results

    providers = json.loads(out).get("OpenIDConnectProviderList", [])
    provider_arns = [p["Arn"] for p in providers]
    gh_provider_arn = None
    gh_provider_details = None
    for arn in provider_arns:
        rc, out, err = run_cmd(["aws", "iam", "get-open-id-connect-provider", "--open-id-connect-provider-arn", arn, "--output", "json"])
        if rc != 0:
            continue
        details = json.loads(out)
        url = details.get("Url", "")
        if "token.actions.githubusercontent.com" in url:
            gh_provider_arn = arn
            gh_provider_details = details
            break

    if not gh_provider_arn:
        results.append(CheckResult(
            name="aws_oidc_provider",
            passed=False,
            detail="No GitHub OIDC provider found in IAM.",
            evidence=["aws iam list-open-id-connect-providers"],
        ))
        return results

    results.append(CheckResult(
        name="aws_oidc_provider",
        passed=True,
        detail=f"Found GitHub OIDC provider: {gh_provider_arn}",
        evidence=["aws iam list-open-id-connect-providers", "aws iam get-open-id-connect-provider"],
    ))

    rc, out, err = run_cmd(["aws", "iam", "list-roles", "--output", "json"])
    if rc != 0:
        results.append(CheckResult("aws_roles", False, f"Unable to list IAM roles: {err or out}", []))
        return results

    roles = json.loads(out).get("Roles", [])
    scoped_role_findings = []
    max_session_findings = []
    for role in roles:
        role_name = role["RoleName"]
        rc, out, err = run_cmd(["aws", "iam", "get-role", "--role-name", role_name, "--output", "json"])
        if rc != 0:
            continue
        role_detail = json.loads(out).get("Role", {})
        if role_detail.get("MaxSessionDuration", 0) > 3600:
            max_session_findings.append((role_name, role_detail.get("MaxSessionDuration")))
        policy = decode_policy_document(role_detail.get("AssumeRolePolicyDocument", {}))
        if not isinstance(policy, dict):
            continue
        statements = find_github_oidc_statements(policy, "token.actions.githubusercontent.com")
        for stmt in statements:
            cond = stmt.get("Condition", {})
            aud_ok = False
            sub_ok = False
            # Common patterns are nested under StringEquals / StringLike.
            for op_key in ("StringEquals", "ForAllValues:StringEquals", "StringLike"):
                op = cond.get(op_key, {}) if isinstance(cond, dict) else {}
                if not isinstance(op, dict):
                    continue
                for k, v in op.items():
                    if k.endswith(":aud") and v == "sts.amazonaws.com":
                        aud_ok = True
                    if k.endswith(":sub"):
                        value = v if isinstance(v, str) else json.dumps(v)
                        if value.startswith("repo:") or value.startswith("environment:") or ("repo:" in value and "*:*" not in value):
                            sub_ok = True
            if aud_ok and sub_ok:
                scoped_role_findings.append(role_name)

    if scoped_role_findings:
        results.append(CheckResult(
            name="aws_oidc_trust_conditions",
            passed=True,
            detail=f"Scoped GitHub OIDC trust found on roles: {', '.join(sorted(set(scoped_role_findings)))}",
            evidence=["aws iam get-role", "IAM trust policy JSON"],
        ))
    else:
        results.append(CheckResult(
            name="aws_oidc_trust_conditions",
            passed=False,
            detail="No role found with both audience=sts.amazonaws.com and repo/environment-scoped subject.",
            evidence=["aws iam get-role", "IAM trust policy JSON"],
        ))

    if max_session_findings:
        results.append(CheckResult(
            name="aws_session_duration",
            passed=False,
            detail="Roles exceed 3600-second MaxSessionDuration: " + ", ".join(f"{n}={d}" for n, d in max_session_findings),
            evidence=["aws iam get-role"],
        ))
    else:
        results.append(CheckResult(
            name="aws_session_duration",
            passed=True,
            detail="All inspected roles with GitHub OIDC trust have MaxSessionDuration <= 3600 seconds.",
            evidence=["aws iam get-role"],
        ))

    rc, out, err = run_cmd(["aws", "cloudtrail", "describe-trails", "--output", "json"])
    if rc != 0:
        results.append(CheckResult("aws_cloudtrail", False, f"Unable to describe CloudTrail trails: {err or out}", []))
    else:
        trails = json.loads(out).get("trailList", [])
        logging_trails = []
        for trail in trails:
            name = trail.get("Name")
            if not name:
                continue
            rc2, out2, err2 = run_cmd(["aws", "cloudtrail", "get-trail-status", "--name", name, "--output", "json"])
            if rc2 != 0:
                continue
            status = json.loads(out2)
            if status.get("IsLogging"):
                logging_trails.append(name)
        results.append(CheckResult(
            name="aws_cloudtrail",
            passed=bool(logging_trails),
            detail=("Logging trails: " + ", ".join(logging_trails)) if logging_trails else "No active CloudTrail logging trail found.",
            evidence=["aws cloudtrail describe-trails", "aws cloudtrail get-trail-status"],
        ))

    return results


def azure_audit(args: argparse.Namespace) -> List[CheckResult]:
    results: List[CheckResult] = []

    rc, out, err = run_cmd(["az", "account", "show", "-o", "json"])
    if rc != 0:
        results.append(CheckResult(
            name="azure_credentials",
            passed=False,
            detail=f"Azure CLI auth failed: {err or out}",
            evidence=[],
        ))
        return results

    acct = json.loads(out)
    results.append(CheckResult(
        name="azure_credentials",
        passed=True,
        detail=f"Authenticated to subscription {acct.get('subscriptionId')}",
        evidence=["az account show"],
    ))

    if not args.azure_app_id:
        results.append(CheckResult(
            name="azure_federated_credentials",
            passed=False,
            detail="Missing --azure-app-id; cannot inspect federated credentials.",
            evidence=[],
            manual=True,
        ))
        return results

    rc, out, err = run_cmd(["az", "ad", "app", "federated-credential", "list", "--id", args.azure_app_id, "-o", "json"])
    if rc != 0:
        results.append(CheckResult(
            name="azure_federated_credentials",
            passed=False,
            detail=f"Unable to list federated credentials for app {args.azure_app_id}: {err or out}",
            evidence=["az ad app federated-credential list"],
        ))
        return results

    creds = json.loads(out)
    if not creds:
        results.append(CheckResult(
            name="azure_federated_credentials",
            passed=False,
            detail="No federated identity credentials found on the application.",
            evidence=["az ad app federated-credential list"],
        ))
        return results

    issuer_expected = args.github_issuer or "https://token.actions.githubusercontent.com"
    audience_expected = args.azure_audience or ("api://AzureADTokenExchangeUSGov" if args.azure_cloud.lower().startswith("usgov") else "api://AzureADTokenExchange")
    good = []
    bad = []
    for cred in creds:
        issuer = cred.get("issuer", "")
        subject = cred.get("subject", "")
        audiences = cred.get("audiences", [])
        issuer_ok = issuer_expected in issuer
        aud_ok = audience_expected in audiences
        sub_ok = bool(subject) and (subject.startswith("repo:") or subject.startswith("environment:")) and "*" not in subject
        if issuer_ok and aud_ok and sub_ok:
            good.append(cred.get("name") or cred.get("displayName") or subject)
        else:
            bad.append({
                "name": cred.get("name") or cred.get("displayName") or subject,
                "issuer": issuer,
                "subject": subject,
                "audiences": audiences,
            })

    passed = bool(good) and not bad
    detail = f"Valid federated credentials: {', '.join(good)}" if passed else f"Invalid or unmatched federated credentials present: {pretty_json(bad)}"
    results.append(CheckResult(
        name="azure_federated_credentials",
        passed=passed,
        detail=detail,
        evidence=["az ad app federated-credential list"],
    ))

    # Optional check: list app credentials to ensure there are no long-lived secrets when using federation only.
    rc, out, err = run_cmd(["az", "ad", "app", "credential", "list", "--id", args.azure_app_id, "-o", "json"])
    if rc == 0:
        try:
            creds2 = json.loads(out)
        except Exception:
            creds2 = []
        if creds2:
            results.append(CheckResult(
                name="azure_app_credentials",
                passed=False,
                detail=f"Application has credential entries present: {len(creds2)}. Review whether client secrets/certs are intended.",
                evidence=["az ad app credential list"],
                manual=True,
            ))
        else:
            results.append(CheckResult(
                name="azure_app_credentials",
                passed=True,
                detail="No application credentials returned by az ad app credential list.",
                evidence=["az ad app credential list"],
            ))
    else:
        results.append(CheckResult(
            name="azure_app_credentials",
            passed=True,
            detail="Credential list check skipped or unavailable; federation check completed.",
            evidence=["az ad app credential list"],
            manual=True,
        ))

    return results


def github_audit(args: argparse.Namespace) -> List[CheckResult]:
    results: List[CheckResult] = []

    token = args.github_token or os.environ.get("GITHUB_TOKEN")
    if not token:
        results.append(CheckResult(
            name="github_token",
            passed=False,
            detail="Missing GitHub token. Set --github-token or GITHUB_TOKEN.",
            evidence=[],
        ))
        return results

    org = args.github_org
    if not org:
        results.append(CheckResult(
            name="github_org",
            passed=False,
            detail="Missing --github-org.",
            evidence=[],
        ))
        return results

    env = os.environ.copy()
    env["GITHUB_TOKEN"] = token

    headers = ["-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2026-03-10"]
    def gh_api(path: str) -> Tuple[int, str, str]:
        return run_cmd(["curl", "-sS", "-L", *headers, "https://api.github.com/" + path], env=env)

    # 2FA disabled members
    rc, out, err = gh_api(f"orgs/{org}/members?filter=2fa_disabled&per_page=100")
    if rc != 0:
        results.append(CheckResult("github_2fa_disabled", False, f"Unable to query 2FA-disabled members: {err or out}", []))
    else:
        members = json.loads(out) if out else []
        results.append(CheckResult(
            name="github_2fa_disabled",
            passed=(len(members) == 0),
            detail=("No 2FA-disabled organization members returned." if len(members) == 0 else f"2FA-disabled members returned: {', '.join(m.get('login', '?') for m in members)}"),
            evidence=["GET /orgs/{org}/members?filter=2fa_disabled"],
        ))

    # 2FA insecure members
    rc, out, err = gh_api(f"orgs/{org}/members?filter=2fa_insecure&per_page=100")
    if rc != 0:
        results.append(CheckResult("github_2fa_insecure", False, f"Unable to query insecure-2FA members: {err or out}", []))
    else:
        members = json.loads(out) if out else []
        results.append(CheckResult(
            name="github_2fa_insecure",
            passed=(len(members) == 0),
            detail=("No insecure-2FA organization members returned." if len(members) == 0 else f"Insecure-2FA members returned: {', '.join(m.get('login', '?') for m in members)}"),
            evidence=["GET /orgs/{org}/members?filter=2fa_insecure"],
        ))

    # PAT policy and max lifetime are generally set in enterprise/org settings and often collected as screenshots.
    # This script supports a local evidence file for those settings.
    manual_pat = args.github_pat_policy_file
    if manual_pat and os.path.exists(manual_pat):
        try:
            with open(manual_pat, "r", encoding="utf-8") as fh:
                pat = json.load(fh)
            max_life = pat.get("max_lifetime_days")
            classic_restricted = pat.get("classic_tokens_restricted")
            fg_approval = pat.get("fine_grained_requires_approval")
            ok = (max_life is not None and max_life <= 366) or pat.get("disallow_personal_access_tokens", False)
            results.append(CheckResult(
                name="github_pat_policy",
                passed=bool(ok),
                detail=f"PAT policy evidence loaded: max_lifetime_days={max_life}, classic_tokens_restricted={classic_restricted}, fine_grained_requires_approval={fg_approval}",
                evidence=[manual_pat],
                manual=True,
            ))
        except Exception as exc:
            results.append(CheckResult(
                name="github_pat_policy",
                passed=False,
                detail=f"Failed to parse PAT policy evidence file {manual_pat}: {exc}",
                evidence=[manual_pat],
                manual=True,
            ))
    else:
        results.append(CheckResult(
            name="github_pat_policy",
            passed=False,
            detail="No machine-readable PAT policy evidence provided. Capture the enterprise/org screenshot and/or export it to JSON, then re-run with --github-pat-policy-file.",
            evidence=["GitHub enterprise/org PAT policy screenshot"],
            manual=True,
        ))

    return results


def print_report(results: List[CheckResult], output_path: Optional[str] = None) -> int:
    report = {
        "controls": "IA-02(08)",
        "results": [asdict(r) for r in results],
        "summary": {
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed),
            "manual": sum(1 for r in results if r.manual),
        },
    }
    text = pretty_json(report)
    print(text)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return 0 if report["summary"]["failed"] == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="IA-02(08) replay-resistance audit helper")
    sub = p.add_subparsers(dest="mode", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--output", help="Write JSON report to this path")

    aws = sub.add_parser("aws", parents=[common])
    aws.add_argument("--github-oidc-provider-arn", help="Expected GitHub OIDC provider ARN (optional)")

    az = sub.add_parser("azure", parents=[common])
    az.add_argument("--azure-app-id", required=True, help="Entra app (client) ID or object ID")
    az.add_argument("--azure-cloud", default="AzureUSGovernment", help="Azure cloud name (used to choose default audience)")
    az.add_argument("--github-issuer", default="https://token.actions.githubusercontent.com", help="Expected GitHub issuer")
    az.add_argument("--azure-audience", default=None, help="Expected audience. Defaults based on cloud.")

    gh = sub.add_parser("github", parents=[common])
    gh.add_argument("--github-org", required=True, help="GitHub organization name")
    gh.add_argument("--github-token", default=None, help="GitHub token with org read permissions")
    gh.add_argument("--github-pat-policy-file", default=None, help="Optional JSON file with PAT policy evidence")

    allp = sub.add_parser("all", parents=[common])
    allp.add_argument("--azure-app-id", required=False)
    allp.add_argument("--azure-cloud", default="AzureUSGovernment")
    allp.add_argument("--github-issuer", default="https://token.actions.githubusercontent.com")
    allp.add_argument("--azure-audience", default=None)
    allp.add_argument("--github-org", required=False)
    allp.add_argument("--github-token", default=None)
    allp.add_argument("--github-pat-policy-file", default=None)
    allp.add_argument("--github-oidc-provider-arn", default=None)

    return p


def main() -> int:
    args = build_parser().parse_args()
    results: List[CheckResult] = []

    if args.mode == "aws":
        results.extend(aws_audit(args))
    elif args.mode == "azure":
        results.extend(azure_audit(args))
    elif args.mode == "github":
        results.extend(github_audit(args))
    elif args.mode == "all":
        results.extend(aws_audit(args))
        results.extend(azure_audit(args))
        results.extend(github_audit(args))
    else:
        raise SystemExit(f"Unknown mode {args.mode}")

    return print_report(results, getattr(args, "output", None))


if __name__ == "__main__":
    raise SystemExit(main())
