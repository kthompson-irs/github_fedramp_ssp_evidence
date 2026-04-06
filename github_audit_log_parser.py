#!/usr/bin/env python3
"""Parse GitHub audit logs and emit a reduced set of security-relevant findings."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
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
    "repo.config.disable_forking",
    "repo.config.allow_actions_disabled",
}

ROUTINE_ACTION_PREFIXES = (
    "repo.download_zip",
    "workflows.",
    "issue_comment.",
    "pull_request.",
    "pull_request_review.",
    "pull_request_review_comment.",
)

SUSPICIOUS_PHRASES = (
    "impossible travel",
    "unusual location",
    "policy bypass",
    "token exposure",
    "token leak",
    "secret leak",
    "credential leak",
    "exfiltration",
    "password spray",
    "credential stuffing",
    "unauthorized access",
    "suspicious oauth",
    "branch protection disabled",
    "required reviews removed",
    "secret scanning disabled",
    "code scanning disabled",
)

AUTH_FAILURE_TERMS = (
    "token",
    "pat",
    "oauth",
    "ssh",
    "password",
    "credential",
)

SENSITIVE_KEY_HINTS = (
    "token",
    "secret",
    "oauth",
    "credential",
    "authorization",
    "auth",
    "password",
    "bearer",
    "pat",
    "key",
)

SEARCH_KEY_HINTS = (
    "action",
    "event",
    "operation",
    "type",
    "actor",
    "user",
    "login",
    "repo",
    "team",
    "message",
    "reason",
    "description",
    "details",
    "note",
    "comment",
    "ip",
    "ip_address",
    "source_ip",
    "client_ip",
    "location",
    "country_code",
    "visibility",
    "status",
    "state",
    "programmatic_access_type",
)

TOKEN_REGEXES = [
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgho_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bghs_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bghu_[A-Za-z0-9_]{20,}\b"),
]

PRIVATE_IP_PREFIXES = (
    "10.",
    "192.168.",
    "127.",
)


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
        ts = float(value)
        if ts > 1_000_000_000_000:
            ts = ts / 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    if isinstance(value, str):
        return value
    return str(value)


def _get_first(d: dict[str, Any], keys: Iterable[str], default: str = "") -> str:
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return str(v)
    return default


def _is_routine_noise(action: str) -> bool:
    return any(action.startswith(prefix) for prefix in ROUTINE_ACTION_PREFIXES)


def _iter_leaf_strings(obj: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[str, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _iter_leaf_strings(v, path + (str(k),))
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_leaf_strings(item, path)
    else:
        if obj not in (None, ""):
            yield (".".join(path).lower(), str(obj))


def _gather_text(event: dict[str, Any]) -> tuple[str, str]:
    search_parts: list[str] = []
    sensitive_parts: list[str] = []

    action = _get_first(event, ("action", "event", "operation", "type"), "unknown")
    actor = _get_first(event, ("actor", "user", "username", "login", "actor_login"), "unknown")
    ts = _normalize_ts(_get_first(event, ("created_at", "timestamp", "time", "occurred_at"), ""))

    search_parts.extend([action, actor, ts])

    for path, value in _iter_leaf_strings(event):
        if any(hint in path for hint in SEARCH_KEY_HINTS):
            search_parts.append(value)
        if any(hint in path for hint in SENSITIVE_KEY_HINTS):
            sensitive_parts.append(value)

    return " ".join(search_parts).lower(), " ".join(sensitive_parts)


def _contains_phrase(text: str, phrases: Iterable[str]) -> Optional[str]:
    for phrase in phrases:
        if phrase in text:
            return phrase
    return None


def _contains_token_like_text(text: str) -> bool:
    return any(rx.search(text) for rx in TOKEN_REGEXES)


def _private_ip_present(event: dict[str, Any]) -> Optional[str]:
    for key in ("ip", "ip_address", "source_ip", "client_ip"):
        v = _get_first(event, (key,), "")
        if v:
            lv = v.lower()
            if lv.startswith(PRIVATE_IP_PREFIXES):
                return v
    return None


def score_event(event: dict[str, Any], include_routine_actions: bool = False) -> Optional[Finding]:
    action = _get_first(event, ("action", "event", "operation", "type"), "unknown")
    actor = _get_first(event, ("actor", "user", "username", "login", "actor_login"), "unknown")
    ts = _normalize_ts(_get_first(event, ("created_at", "timestamp", "time", "occurred_at"), ""))

    if not include_routine_actions and _is_routine_noise(action) and action not in HIGH_RISK_ACTIONS:
        return None

    search_blob, sensitive_blob = _gather_text(event)

    reasons: list[str] = []
    severity: Optional[str] = None
    category: Optional[str] = None

    if action in HIGH_RISK_ACTIONS:
        severity = "HIGH"
        category = "privilege_or_security_change"
        reasons.append(f"High-risk action '{action}' is in the watch list.")

    if _contains_token_like_text(sensitive_blob):
        severity = "HIGH"
        category = category or "token_exposure"
        reasons.append("Token-like value detected in a sensitive field.")

    phrase = _contains_phrase(search_blob, SUSPICIOUS_PHRASES)
    if phrase:
        if severity is None:
            severity = "MEDIUM"
            category = "suspicious_content"
        reasons.append(f"Event contains suspicious phrase '{phrase}'.")

    if "failed" in search_blob and any(term in search_blob for term in AUTH_FAILURE_TERMS):
        severity = "HIGH" if severity != "HIGH" else severity
        category = category or "auth_failure"
        reasons.append("Authentication or token failure pattern detected.")

    private_ip = _private_ip_present(event)
    if private_ip and "vpn" not in search_blob and "corp" not in search_blob and severity is None:
        severity = "LOW"
        category = "internal_network_activity"
        reasons.append(f"Private/internal IP observed: {private_ip}.")

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

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_no}: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse GitHub audit logs for security-relevant findings.")
    parser.add_argument("--input", required=True, help="Path to GitHub audit log JSON or JSONL file")
    parser.add_argument("--output", required=True, help="Path to findings JSON output file")
    parser.add_argument(
        "--include-routine-actions",
        action="store_true",
        help="Include routine workflow/comment/PR actions instead of skipping them by default",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not input_path.exists():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    seen: set[str] = set()
    total = 0
    skipped = 0

    for event in iter_events(input_path):
        total += 1
        finding = score_event(event, include_routine_actions=args.include_routine_actions)
        if not finding:
            if not args.include_routine_actions and _is_routine_noise(_get_first(event, ("action", "event", "operation", "type"), "unknown")):
                skipped += 1
            continue

        dedupe_key = json.dumps(
            {
                "severity": finding.severity,
                "category": finding.category,
                "timestamp": finding.timestamp,
                "actor": finding.actor,
                "action": finding.action,
                "reason": finding.reason,
            },
            sort_keys=True,
            ensure_ascii=False,
        )

        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        findings.append(finding)

    output_path.write_text(
        json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )

    print(f"Processed events: {total}")
    print(f"Findings: {len(findings)}")
    print(f"Skipped routine events: {skipped}")
    for f in findings[:100]:
        print(
            f"[{f.severity}] {f.timestamp} actor={f.actor} action={f.action} "
            f"category={f.category} reason={f.reason}"
        )

    if len(findings) > 100:
        print(f"... truncated {len(findings) - 100} additional findings")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
