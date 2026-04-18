"""FedRAMP Evidence Collector Starter Kit

Purpose:
- Pull SI-03 and related FedRAMP evidence from GitHub, AWS GovCloud, and Azure Government.
- Normalize evidence into a single dashboard-friendly data model.
- Expose a small API for a dashboard / SharePoint / Power BI ingestion flow.

This is starter code. Replace placeholders with your real org/repo/account/subscription IDs.

Dependencies:
  pip install fastapi uvicorn requests boto3 azure-identity pydantic

Environment variables:
  GITHUB_TOKEN=...
  GITHUB_ORG=...
  GITHUB_REPOS=repo1,repo2

  AWS_REGION=us-gov-west-1
  AWS_PROFILE=optional-profile

  AZURE_SUBSCRIPTION_ID=...
  AZURE_TENANT_ID=...
  AZURE_CLIENT_ID=...
  AZURE_CLIENT_SECRET=...
  AZURE_RESOURCE_GROUPS=rg1,rg2 (optional for filtering)
"""

from __future__ import annotations

import json
import os
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import boto3
import requests
from azure.identity import ClientSecretCredential
from fastapi import FastAPI
from pydantic import BaseModel, Field


# -----------------------------
# Data model
# -----------------------------

class EvidenceStatus(str, Enum):
    ready = "Ready"
    pending = "Pending"
    failed = "Failed"


class EvidenceItem(BaseModel):
    control_id: str
    control_family: str
    source: str
    artifact_type: str
    artifact_name: str
    timestamp_utc: str
    status: EvidenceStatus = EvidenceStatus.ready
    owner: Optional[str] = None
    evidence_uri: Optional[str] = None
    checksum: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class CollectorHealth(BaseModel):
    source: str
    healthy: bool
    last_run_utc: str
    message: Optional[str] = None


class DashboardSnapshot(BaseModel):
    generated_at_utc: str
    evidence_count: int
    ready_count: int
    pending_count: int
    failed_count: int
    collectors: List[CollectorHealth]
    evidence: List[EvidenceItem]


# -----------------------------
# Collector base
# -----------------------------

class BaseCollector(ABC):
    @abstractmethod
    def collect(self) -> List[EvidenceItem]:
        raise NotImplementedError

    def health(self, healthy: bool, message: Optional[str] = None) -> CollectorHealth:
        return CollectorHealth(
            source=self.__class__.__name__,
            healthy=healthy,
            last_run_utc=utc_now(),
            message=message,
        )


# -----------------------------
# GitHub collector
# -----------------------------

class GitHubCollector(BaseCollector):
    def __init__(self, token: str, org: Optional[str] = None, repos: Optional[List[str]] = None):
        self.token = token
        self.org = org
        self.repos = repos or []
        self.base_url = "https://api.github.com"
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )

    def _repo_targets(self) -> List[str]:
        if self.repos:
            return self.repos
        if self.org:
            # Starter fallback: list repos for org if not provided.
            url = f"{self.base_url}/orgs/{self.org}/repos?per_page=100"
            data = self._get_json(url)
            return [r["name"] for r in data]
        return []

    def _get_json(self, url: str) -> Any:
        resp = self.session.get(url, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def collect(self) -> List[EvidenceItem]:
        items: List[EvidenceItem] = []
        for repo in self._repo_targets():
            items.extend(self._collect_repo(repo))
        return items

    def _collect_repo(self, repo: str) -> List[EvidenceItem]:
        items: List[EvidenceItem] = []

        # Code scanning alerts
        code_alerts = self._get_json(f"{self.base_url}/repos/{self.org}/{repo}/code-scanning/alerts?per_page=100")
        items.append(
            EvidenceItem(
                control_id="SI-03",
                control_family="SI",
                source="GitHub",
                artifact_type="code_scanning_alerts",
                artifact_name=f"{repo} code scanning alerts",
                timestamp_utc=utc_now(),
                evidence_uri=f"github://{self.org}/{repo}/code-scanning/alerts",
                details={"count": len(code_alerts), "sample": code_alerts[:3]},
            )
        )

        # Secret scanning alerts
        try:
            secret_alerts = self._get_json(f"{self.base_url}/repos/{self.org}/{repo}/secret-scanning/alerts?per_page=100")
            items.append(
                EvidenceItem(
                    control_id="SI-03",
                    control_family="SI",
                    source="GitHub",
                    artifact_type="secret_scanning_alerts",
                    artifact_name=f"{repo} secret scanning alerts",
                    timestamp_utc=utc_now(),
                    evidence_uri=f"github://{self.org}/{repo}/secret-scanning/alerts",
                    details={"count": len(secret_alerts), "sample": secret_alerts[:3]},
                )
            )
        except requests.HTTPError as exc:
            items.append(
                EvidenceItem(
                    control_id="SI-03",
                    control_family="SI",
                    source="GitHub",
                    artifact_type="secret_scanning_alerts",
                    artifact_name=f"{repo} secret scanning alerts",
                    timestamp_utc=utc_now(),
                    status=EvidenceStatus.pending,
                    evidence_uri=f"github://{self.org}/{repo}/secret-scanning/alerts",
                    details={"error": str(exc), "note": "Repository may not have secret scanning enabled."},
                )
            )

        # Dependabot alerts
        dep_alerts = self._get_json(f"{self.base_url}/repos/{self.org}/{repo}/dependabot/alerts?per_page=100")
        items.append(
            EvidenceItem(
                control_id="SI-03",
                control_family="SI",
                source="GitHub",
                artifact_type="dependabot_alerts",
                artifact_name=f"{repo} Dependabot alerts",
                timestamp_utc=utc_now(),
                evidence_uri=f"github://{self.org}/{repo}/dependabot/alerts",
                details={"count": len(dep_alerts), "sample": dep_alerts[:3]},
            )
        )

        # Branch protection
        try:
            branch_rules = self._get_json(f"{self.base_url}/repos/{self.org}/{repo}/branches/main/protection")
            items.append(
                EvidenceItem(
                    control_id="AC-3",
                    control_family="AC",
                    source="GitHub",
                    artifact_type="branch_protection",
                    artifact_name=f"{repo} branch protection",
                    timestamp_utc=utc_now(),
                    evidence_uri=f"github://{self.org}/{repo}/branches/main/protection",
                    details=branch_rules,
                )
            )
        except requests.HTTPError as exc:
            items.append(
                EvidenceItem(
                    control_id="AC-3",
                    control_family="AC",
                    source="GitHub",
                    artifact_type="branch_protection",
                    artifact_name=f"{repo} branch protection",
                    timestamp_utc=utc_now(),
                    status=EvidenceStatus.pending,
                    evidence_uri=f"github://{self.org}/{repo}/branches/main/protection",
                    details={"error": str(exc)},
                )
            )

        return items


# -----------------------------
# AWS collector
# -----------------------------

class AWSCollector(BaseCollector):
    def __init__(self, region: str, profile: Optional[str] = None):
        session_kwargs: Dict[str, Any] = {"region_name": region}
        if profile:
            session_kwargs["profile_name"] = profile
        self.session = boto3.Session(**session_kwargs)
        self.config = self.session.client("config")
        self.guardduty = self.session.client("guardduty")

    def collect(self) -> List[EvidenceItem]:
        items: List[EvidenceItem] = []
        items.extend(self._collect_config())
        items.extend(self._collect_guardduty())
        return items

    def _collect_config(self) -> List[EvidenceItem]:
        items: List[EvidenceItem] = []
        # Starter pattern: collect compliance by rule and flatten the summary.
        rules = self.config.describe_config_rules().get("ConfigRules", [])
        for rule in rules:
            rule_name = rule.get("ConfigRuleName")
            if not rule_name:
                continue
            compliance = self.config.describe_compliance_by_config_rule(ConfigRuleNames=[rule_name])
            items.append(
                EvidenceItem(
                    control_id="CM-8",
                    control_family="CM",
                    source="AWS Config",
                    artifact_type="config_rule_compliance",
                    artifact_name=rule_name,
                    timestamp_utc=utc_now(),
                    evidence_uri=f"awsconfig://config-rule/{rule_name}",
                    details=compliance,
                )
            )
        return items

    def _collect_guardduty(self) -> List[EvidenceItem]:
        items: List[EvidenceItem] = []
        detectors = self.guardduty.list_detectors().get("DetectorIds", [])
        for detector_id in detectors:
            finding_ids = self.guardduty.list_findings(detectorId=detector_id).get("FindingIds", [])
            findings = []
            if finding_ids:
                findings = self.guardduty.get_findings(detectorId=detector_id, findingIds=finding_ids[:50]).get("Findings", [])
            items.append(
                EvidenceItem(
                    control_id="SI-03",
                    control_family="SI",
                    source="GuardDuty",
                    artifact_type="guardduty_findings",
                    artifact_name=f"Detector {detector_id}",
                    timestamp_utc=utc_now(),
                    evidence_uri=f"guardduty://detector/{detector_id}/findings",
                    details={"finding_count": len(finding_ids), "sample": findings[:3]},
                )
            )
        return items


# -----------------------------
# Azure collector
# -----------------------------

class AzureCollector(BaseCollector):
    def __init__(self, tenant_id: str, client_id: str, client_secret: str, subscription_id: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.subscription_id = subscription_id
        self.credential = ClientSecretCredential(tenant_id, client_id, client_secret)

    def _token(self, scope: str) -> str:
        return self.credential.get_token(scope).token

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token('https://management.azure.com/.default')}",
            "Content-Type": "application/json",
        }

    def collect(self) -> List[EvidenceItem]:
        items: List[EvidenceItem] = []
        items.extend(self._collect_policy_compliance())
        items.extend(self._collect_defender_alerts())
        return items

    def _collect_policy_compliance(self) -> List[EvidenceItem]:
        # Azure Policy compliance via policy states summarize endpoint.
        url = (
            f"https://management.azure.com/subscriptions/{self.subscription_id}"
            f"/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2022-04-01"
        )
        resp = requests.post(url, headers=self._headers(), json={"groupBy": "PolicyAssignmentId"}, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return [
            EvidenceItem(
                control_id="CM-6",
                control_family="CM",
                source="Azure Policy",
                artifact_type="policy_compliance_summary",
                artifact_name=f"Subscription {self.subscription_id} policy compliance",
                timestamp_utc=utc_now(),
                evidence_uri=f"azurepolicy://subscriptions/{self.subscription_id}/policyStates/latest/summarize",
                details=data,
            )
        ]

    def _collect_defender_alerts(self) -> List[EvidenceItem]:
        url = (
            f"https://management.azure.com/subscriptions/{self.subscription_id}"
            f"/providers/Microsoft.Security/alerts?api-version=2022-01-01"
        )
        resp = requests.get(url, headers=self._headers(), timeout=30)
        resp.raise_for_status()
        data = resp.json()
        alerts = data.get("value", data)
        return [
            EvidenceItem(
                control_id="SI-03",
                control_family="SI",
                source="Defender for Cloud",
                artifact_type="security_alerts",
                artifact_name=f"Subscription {self.subscription_id} security alerts",
                timestamp_utc=utc_now(),
                evidence_uri=f"azuredefender://subscriptions/{self.subscription_id}/alerts",
                details={"count": len(alerts), "sample": alerts[:3]},
            )
        ]


# -----------------------------
# Aggregation and API
# -----------------------------

class DashboardStore:
    def __init__(self) -> None:
        self._items: List[EvidenceItem] = []
        self._collectors: List[CollectorHealth] = []
        self._updated_at = utc_now()

    def refresh(self, items: List[EvidenceItem], collector_health: List[CollectorHealth]) -> None:
        self._items = items
        self._collectors = collector_health
        self._updated_at = utc_now()

    def snapshot(self) -> DashboardSnapshot:
        ready = sum(1 for i in self._items if i.status == EvidenceStatus.ready)
        pending = sum(1 for i in self._items if i.status == EvidenceStatus.pending)
        failed = sum(1 for i in self._items if i.status == EvidenceStatus.failed)
        return DashboardSnapshot(
            generated_at_utc=self._updated_at,
            evidence_count=len(self._items),
            ready_count=ready,
            pending_count=pending,
            failed_count=failed,
            collectors=self._collectors,
            evidence=self._items,
        )


def run_collectors() -> tuple[List[EvidenceItem], List[CollectorHealth]]:
    items: List[EvidenceItem] = []
    health: List[CollectorHealth] = []

    github_token = os.getenv("GITHUB_TOKEN", "")
    github_org = os.getenv("GITHUB_ORG")
    github_repos = [r.strip() for r in os.getenv("GITHUB_REPOS", "").split(",") if r.strip()]
    aws_region = os.getenv("AWS_REGION", "us-gov-west-1")
    aws_profile = os.getenv("AWS_PROFILE")
    azure_subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID", "")
    azure_tenant_id = os.getenv("AZURE_TENANT_ID", "")
    azure_client_id = os.getenv("AZURE_CLIENT_ID", "")
    azure_client_secret = os.getenv("AZURE_CLIENT_SECRET", "")

    if github_token and github_org:
        try:
            collector = GitHubCollector(github_token, github_org, github_repos)
            collected = collector.collect()
            items.extend(collected)
            health.append(collector.health(True, f"Collected {len(collected)} items"))
        except Exception as exc:  # noqa: BLE001
            health.append(CollectorHealth(source="GitHubCollector", healthy=False, last_run_utc=utc_now(), message=str(exc)))
    else:
        health.append(CollectorHealth(source="GitHubCollector", healthy=False, last_run_utc=utc_now(), message="Missing GITHUB_TOKEN or GITHUB_ORG"))

    try:
        collector = AWSCollector(region=aws_region, profile=aws_profile)
        collected = collector.collect()
        items.extend(collected)
        health.append(collector.health(True, f"Collected {len(collected)} items"))
    except Exception as exc:  # noqa: BLE001
        health.append(CollectorHealth(source="AWSCollector", healthy=False, last_run_utc=utc_now(), message=str(exc)))

    if azure_subscription_id and azure_tenant_id and azure_client_id and azure_client_secret:
        try:
            collector = AzureCollector(
                tenant_id=azure_tenant_id,
                client_id=azure_client_id,
                client_secret=azure_client_secret,
                subscription_id=azure_subscription_id,
            )
            collected = collector.collect()
            items.extend(collected)
            health.append(collector.health(True, f"Collected {len(collected)} items"))
        except Exception as exc:  # noqa: BLE001
            health.append(CollectorHealth(source="AzureCollector", healthy=False, last_run_utc=utc_now(), message=str(exc)))
    else:
        health.append(CollectorHealth(source="AzureCollector", healthy=False, last_run_utc=utc_now(), message="Missing Azure credential variables"))

    return items, health


store = DashboardStore()
app = FastAPI(title="FedRAMP Evidence Dashboard API", version="0.1.0")


@app.on_event("startup")
def startup_refresh() -> None:
    items, health = run_collectors()
    store.refresh(items, health)


@app.get("/health")
def health() -> Dict[str, Any]:
    snapshot = store.snapshot()
    return {
        "status": "ok",
        "generated_at_utc": snapshot.generated_at_utc,
        "collector_count": len(snapshot.collectors),
    }


@app.get("/snapshot", response_model=DashboardSnapshot)
def get_snapshot() -> DashboardSnapshot:
    return store.snapshot()


@app.post("/refresh", response_model=DashboardSnapshot)
def refresh() -> DashboardSnapshot:
    items, health = run_collectors()
    store.refresh(items, health)
    return store.snapshot()


# -----------------------------
# Utilities
# -----------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    # Manual run for quick testing:
    #   uvicorn fedramp_evidence_collectors_and_dashboard:app --reload
    items, health = run_collectors()
    store.refresh(items, health)
    print(json.dumps(store.snapshot().model_dump(), indent=2))
