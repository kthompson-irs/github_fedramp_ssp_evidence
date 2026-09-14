#!/usr/bin/env python3 
import os,json,requests,pandas as pd
from collections import Counter,defaultdict
from datetime import datetime,timedelta,timezone

ENTERPRISE=os.environ["ENTERPRISE"]
TOKEN=os.environ["GH_TOKEN"]
DAYS=int(os.getenv("DAYS","30"))

cutoff=(datetime.now(timezone.utc)-timedelta(days=DAYS)).isoformat().replace("+00:00","Z")

headers={
 "Authorization":f"Bearer {TOKEN}",
 "Accept":"application/vnd.github+json",
 "X-GitHub-Api-Version":"2022-11-28"
}

url=f"https://api.github.com/enterprises/{ENTERPRISE}/audit-log"
params={"per_page":100,"phrase":f"created:>={cutoff}"}

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
with open(f"reports/raw_audit_log_{DAYS}_days.json","w") as f: json.dump(events,f,indent=2)

uc=Counter(); uac=defaultdict(Counter); detail=[]
for e in events: 
    actor=e.get("actor","Unknown"); action=e.get("action","Unknown"); ts=e.get("@timestamp","")
    uc[actor]+=1; uac[actor][action]+=1
    detail.append({
      "Timestamp":ts,"Date":ts[:10],"User":actor,"Action":action,
      "Organization":e.get("org",""),"Repository":e.get("repo",""),
      "IP Address":e.get("actor_ip",""),"Country":e.get("country_code","")
    })

pd.DataFrame([{"User":u,"Total Actions":c} for u,c in uc.most_common()]).to_csv(f"reports/user_summary_{DAYS}_days.csv",index=False)
rows=[]
for u in sorted(uac):
    for a,c in sorted(uac[u].items()):
        rows.append({"User":u,"Action":a,"Count":c})
pd.DataFrame(rows).to_csv(f"reports/user_action_summary_{DAYS}_days.csv",index=False)
d=pd.DataFrame(detail)
if not d.empty: d=d.sort_values("Timestamp",ascending=False)
d.to_csv(f"reports/user_activity_details_{DAYS}_days.csv",index=False)
print(f"Generated {len(events)} events for last {DAYS} days.") 
