#!/usr/bin/env python3
import os,json,requests,pandas as pd
from collections import Counter,defaultdict

ENTERPRISE=os.environ["ENTERPRISE"]
TOKEN=os.environ["GH_TOKEN"]

headers={
 "Authorization":f"Bearer {TOKEN}",
 "Accept":"application/vnd.github+json",
 "X-GitHub-Api-Version":"2022-11-28"
}

url=f"https://api.github.com/enterprises/{ENTERPRISE}/audit-log"
params={"per_page":100}
events=[]

while url:
    r=requests.get(url,headers=headers,params=params,timeout=60)
    r.raise_for_status()
    events.extend(r.json())
    nxt=None
    if "Link" in r.headers:
        for part in r.headers["Link"].split(","):
            if 'rel="next"' in part:
                nxt=part.split(";")[0].strip()[1:-1]
    url=nxt 
    params=None

os.makedirs("reports",exist_ok=True)

with open("reports/raw_audit_log.json","w") as f:
    json.dump(events,f,indent=2)

user_counter=Counter()
user_action_counter=defaultdict(Counter)
detail=[]

for e in events: 
    actor=e.get("actor","Unknown")
    action=e.get("action","Unknown")
    ts=e.get("@timestamp","")
    user_counter[actor]+=1
    user_action_counter[actor][action]+=1
    detail.append({
        "Timestamp":ts,
        "Date":ts[:10],
        "User":actor,
        "Action":action,
        "Organization":e.get("org",""),
        "Repository":e.get("repo",""),
        "IP Address":e.get("actor_ip",""),
        "Transport":e.get("transport_protocol",""),
        "Country":e.get("country_code",""),
        "User Agent":e.get("user_agent",""),
    })

pd.DataFrame(
    [{"User":u,"Total Actions":c} for u,c in user_counter.most_common()]
).to_csv("reports/user_summary.csv",index=False)

rows=[]
for u in sorted(user_action_counter):
    for a,c in sorted(user_action_counter[u].items()):
        rows.append({"User":u,"Action":a,"Count":c})
pd.DataFrame(rows).to_csv("reports/user_action_summary.csv",index=False)

rows=[]
for u in sorted(user_action_counter):
    for a,c in sorted(user_action_counter[u].items()):
        rows.append({"User":u,"Action":a,"Count":c})
pd.DataFrame(rows).to_csv("reports/user_action_summary.csv",index=False)

d=pd.DataFrame(detail)
if not d.empty:
    d=d.sort_values("Timestamp",ascending=False)
d.to_csv("reports/user_activity_details.csv",index=False)

with open("reports/user_activity_summary.json","w") as f:
    json.dump({u:dict(v) for u,v in user_action_counter.items()},f,indent=2)

print(f"Processed {len(events)} events")
