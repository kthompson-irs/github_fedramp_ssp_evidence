#!/usr/bin/env python3 
import os
import json
import requests
import pandas as pd
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

ENTERPRISE = os.getenv("ENTERPRISE", "internal-revenue-service")
TOKEN = os.environ["FEDRAMP_ENTERPRISE_TOKEN"]

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

def normalize_timestamp(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        if value > 1000000000000:
            value /= 1000 
        return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)

def get_nested(obj, *keys): 
    cur = obj
    for k in keys:
        if isinstance(cur, dict):
            cur = cur.get(k)
        else:   
            return ""
    return cur if cur is not None else "" 

def fetch_events(days):
    cutoff = (datetime.now(timezone.utc)-timedelta(days=days)).strftime("%Y-%m-%d")
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    url = f"https://api.github.com/enterprises/{ENTERPRISE}/audit-log"
    params = {"per_page":100, "phrase":f"created:{cutoff}..{today}"}
    events=[]
    while url:
        r=requests.get(url, headers=HEADERS, params=params, timeout=60)
        if r.status_code!=200:
            print("HTTP", r.status_code)
            print(r.text)
            r.raise_for_status()
        events.extend(r.json())
        next_url=None
        link=r.headers.get("Link","")
        for part in link.split(","):
            if 'rel="next"' in part:
                next_url=part.split(";")[0].strip()[1:-1]
        url=next_url
        params=None
    return events

os.makedirs("reports", exist_ok=True)

for DAYS in (30,60,90):
    events=fetch_events(DAYS)
    with open(f"reports/raw_audit_log_{DAYS}_days.json","w") as f:
        json.dump(events,f,indent=2)

    user_counter=Counter()
    action_counter=defaultdict(Counter)
    detail=[]

    for e in events:
        actor=get_nested(e,"actor") or "Unknown"
        action=e.get("action","Unknown")
        ts=normalize_timestamp(e.get("@timestamp"))
        repo=e.get("repo")
        if isinstance(repo,dict):
            repo=repo.get("name","")
        org=e.get("org")
        if isinstance(org,dict):
            org=org.get("name","")
        user_counter[actor]+=1
        action_counter[actor][action]+=1
        detail.append({
            "Timestamp":ts,
            "Date":ts[:10] if ts else "",
            "User":actor,
            "Action":action,
            "Organization":org or "",
            "Repository":repo or "",
            "IP Address":e.get("actor_ip",""),
            "Country":e.get("country_code",""),
            "Transport":e.get("transport_protocol",""),
            "User Agent":e.get("user_agent","")
        })

    pd.DataFrame([{"User":u,"Total Actions":c} for u,c in user_counter.most_common()]).to_csv(
        f"reports/user_summary_{DAYS}_days.csv",index=False)

    rows=[]
    for u in sorted(action_counter):
        for a,c in sorted(action_counter[u].items()):
            rows.append({"User":u,"Action":a,"Count":c})
    pd.DataFrame(rows).to_csv(f"reports/user_action_summary_{DAYS}_days.csv",index=False)

    d=pd.DataFrame(detail)
    if not d.empty:
        d=d.sort_values("Timestamp",ascending=False)
    d.to_csv(f"reports/user_activity_details_{DAYS}_days.csv",index=False)

    with open(f"reports/user_activity_summary_{DAYS}_days.json","w") as f:
        json.dump({u:dict(v) for u,v in action_counter.items()},f,indent=2)

    print(f"Generated {len(events)} events for {DAYS} days")
