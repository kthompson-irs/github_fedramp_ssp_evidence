#!/usr/bin/env python3
"""
GitHub audit log parser for risky activity detection.

Flags:
  - token misuse patterns
  - suspicious authentication events
  - privilege changes
  - repository policy bypasses
  - anomalous actor/IP combinations

Usage:
  python github_audit_log_parser.py --input audit.log.jsonl
  python github_audit_log_parser.py --input audit.log.jsonl --output findings.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional


HIGH_RISK_ACTIONS = {
    "oauth_authorization.create",
    "oauth_authorization.destroy",
    "personal_access_token.create",
    "personal_access_token.update",
    "personal_access_token.delete",
    "personal_access_token.grant",
    "github_app.authorized",
    "github_app.revoked",
    "org.add_member",
    "org.remove_member",
    "team.add_member",
    "team.remove_member",
    "repo.config.disable_branch_protection",
    "repo.config.remove_required_reviews",
    "repo.config.disable_secret_scanning",
    "repo.config.disable_code_scanning",
    "repo.config.change_visibility",
}

SUSPICIOUS_KEYWORDS = (
    "token",
    "pat",
    "ssh key",
    "oauth",
    "bypass",
    "disable",
    "revoked",
    "grant",
    "downloaded",
    "exfiltration",
    "impossible travel",
    "unusual location",
)

TOKEN_REGEXES = [
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),  # GitHub-like token formats
    re.compile(r"\b[A-Za-z0-9_/-]{36,}\b"),         # generic long opaque tokens
]


@dataclass
class Finding:
    severity: str
    category: str
    timestamp: str
    actor: str
    action: str
    reason: str
    raw: dict[str, Any]


def _normalize_ts(value: Any) -> str:
    if not value:
        return ""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    if isinstance(value, str):
        return value
    return str(value)


def _get_first(d: dict[str, Any], keys: Iterable[str], default: str = "") -> str:
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return str(v)
    return default


def _contains_token_like_text(text: str) -> bool:
    if not text:
        return False
    for rx in TOKEN_REGEXES:
        if rx.search(text):
            return True
    return False


def score_event(event: dict[str, Any]) -> Optional[Finding]:
    # Normalize common fields across audit log schemas
    action = _get_first(event, ("action", "event", "operation", "type"), "unknown")
    actor = _get_first(event, ("actor", "user", "username", "login", "actor_login"), "unknown")
    ts = _normalize_ts(_get_first(event, ("created_at", "timestamp", "time", "occurred_at"), ""))

    # Build a searchable text blob
    searchable = json.dumps(event, sort_keys=True, default=str).lower()

    reasons: list[str] = []
    severity = None
    category = None

    if action in HIGH_RISK_ACTIONS:
        severity = "HIGH"
        category = "privilege_or_security_change"
        reasons.append(f"High-risk action '{action}' is in the deny/watch list.")

    if any(keyword in searchable for keyword in SUSPICIOUS_KEYWORDS):
        if severity is None:
            severity = "MEDIUM"
            category = "suspicious_content"
        reasons.append("Event contains suspicious keywords associated with token misuse or policy bypass.")

    # Token-like values embedded in raw fields
    if _contains_token_like_text(searchable):
        severity = "HIGH" if severity in (None, "MEDIUM") else severity
        category = category or "token_exposure"
        reasons.append("Token-like value detected in event payload.")

    # Specific fields often worth flagging
    ip = _get_first(event, ("ip", "ip_address", "source_ip", "client_ip"), "")
    if ip and ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "192.168.")):
        # Not automatically bad, but useful if it appears in an unusual context
        if "vpn" not in searchable and "corp" not in searchable and severity is None:
            severity = "LOW"
            category = "internal_network_activity"
            reasons.append("Internal/private IP observed; review for expected source context.")

    if "failed" in searchable and any(x in searchable for x in ("token", "pat", "oauth", "ssh")):
        severity = "HIGH" if severity != "HIGH" else severity
        category = category or "auth_failure"
        reasons.append("Repeated authentication/token failure behavior may indicate misuse or brute force.")

    if not reasons:
        return None

    return Finding(
        severity=severity or "LOW",
        category=category or "general_review",
        timestamp=ts,
        actor=actor,
        action=action,
        reason=" ".join(reasons),
        raw=event,
    )


def iter_events(path: Path) -> Iterable[dict[str, Any]]:
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            yield from data
        else:
            yield data
        return

    # JSONL fallback
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON on line {line_no}: {e}") from e


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse GitHub audit logs for risky activity.")
    parser.add_argument("--input", required=True, help="Path to GitHub audit log JSON/JSONL file")
    parser.add_argument("--output", help="Optional output path for findings JSON")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    total = 0

    for event in iter_events(input_path):
        total += 1
        finding = score_event(event)
        if finding:
            findings.append(finding)

    # Print human-readable summary
    print(f"Processed events: {total}")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(
            f"[{f.severity}] {f.timestamp} actor={f.actor} action={f.action} "
            f"category={f.category} reason={f.reason}"
        )

    if args.output:
        out = Path(args.output)
        out.write_text(
            json.dumps([asdict(f) for f in findings], indent=2, default=str),
            encoding="utf-8",
        )
        print(f"Wrote findings to {out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
