mport React, { useMemo, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { RefreshCw, ShieldCheck, AlertTriangle, FileSearch, Cloud, Github } from "lucide-react";

const evidence = [
  { control: "SI-03", source: "GitHub", artifact: "Code scanning alerts", status: "Ready", updated: "2026-03-31 08:15" },
  { control: "SI-03", source: "GitHub", artifact: "Secret scanning alerts", status: "Ready", updated: "2026-03-31 08:15" },
  { control: "SI-03", source: "AWS", artifact: "Config compliance", status: "Ready", updated: "2026-03-31 08:10" },
  { control: "SI-03", source: "Azure", artifact: "Policy compliance", status: "Ready", updated: "2026-03-31 08:10" },
  { control: "AU-2", source: "AWS", artifact: "CloudTrail coverage", status: "Pending", updated: "2026-03-31 08:05" },
  { control: "AC-2", source: "Azure", artifact: "RBAC export", status: "Ready", updated: "2026-03-31 08:02" },
];

const collectors = [
  { name: "GitHub Collector", status: "Healthy", detail: "GHAS, Dependabot, branch protection", icon: Github },
  { name: "AWS Collector", status: "Healthy", detail: "Config, Inspector, GuardDuty", icon: Cloud },
  { name: "Azure Collector", status: "Healthy", detail: "Policy, Resource Graph, Defender", icon: Cloud },
];

const controlSummary = [
  { name: "AC", pct: 92, text: "Access control evidence complete" },
  { name: "IA", pct: 88, text: "MFA and auth evidence complete" },
  { name: "AU", pct: 79, text: "Log coverage needs review" },
  { name: "CM", pct: 85, text: "Baseline and drift checks complete" },
  { name: "SI", pct: 96, text: "Malicious code protections complete" },
  { name: "IR", pct: 74, text: "Incident drill evidence pending" },
];

function statusBadge(status) {
  const tone = status === "Ready" || status === "Healthy"
    ? "bg-emerald-100 text-emerald-700 border-emerald-200"
    : status === "Pending"
      ? "bg-amber-100 text-amber-700 border-amber-200"
      : "bg-rose-100 text-rose-700 border-rose-200";
  return <Badge className={`border ${tone}`}>{status}</Badge>;
}

export default function FedRAMPComplianceDashboard() {
  const [lastRefresh, setLastRefresh] = useState("2026-03-31 08:15");
  const [selectedFamily, setSelectedFamily] = useState("All");

  const filteredEvidence = useMemo(() => {
    if (selectedFamily === "All") return evidence;
    return evidence.filter((row) => row.control.startsWith(selectedFamily));
  }, [selectedFamily]);

  const metrics = [
    { label: "Evidence Ready", value: "84%", sub: "21 of 25 artifacts", icon: ShieldCheck },
    { label: "Open Findings", value: "3", sub: "1 high, 2 moderate", icon: AlertTriangle },
    { label: "Collector Health", value: "100%", sub: "3 of 3 sources healthy", icon: Cloud },
    { label: "Last Sync", value: lastRefresh, sub: "GitHub / AWS / Azure", icon: FileSearch },
  ];

  return (
    <div className="min-h-screen bg-slate-50 p-6 text-slate-900">
      <div className="mx-auto max-w-7xl space-y-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-3xl font-semibold tracking-tight">FedRAMP Evidence Dashboard</h1>
            <p className="mt-1 text-sm text-slate-600">
              Live view for GitHub, AWS GovCloud, and Azure Government evidence collection.
            </p>
          </div>
          <Button
            onClick={() => setLastRefresh(new Date().toISOString().slice(0, 16).replace("T", " "))}
            className="gap-2"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </Button>
        </div>

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {metrics.map((m) => {
            const Icon = m.icon;
            return (
              <Card key={m.label} className="rounded-2xl shadow-sm">
                <CardContent className="p-5">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-slate-600">{m.label}</p>
                      <div className="mt-2 text-2xl font-semibold">{m.value}</div>
                      <p className="mt-1 text-xs text-slate-500">{m.sub}</p>
                    </div>
                    <div className="rounded-2xl bg-slate-100 p-3">
                      <Icon className="h-5 w-5 text-slate-700" />
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>

        <div className="grid gap-4 xl:grid-cols-3">
          <Card className="rounded-2xl shadow-sm xl:col-span-2">
            <CardHeader>
              <CardTitle>Control Family Coverage</CardTitle>
              <CardDescription>Use this to see which control families need evidence or remediation.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {controlSummary.map((c) => (
                <div key={c.name} className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="font-medium">{c.name}</span>
                    <span className="text-slate-500">{c.pct}%</span>
                  </div>
                  <Progress value={c.pct} />
                  <p className="text-xs text-slate-500">{c.text}</p>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card className="rounded-2xl shadow-sm">
            <CardHeader>
              <CardTitle>Collectors</CardTitle>
              <CardDescription>Operational status for evidence pulls.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {collectors.map((c) => {
                const Icon = c.icon;
                return (
                  <div key={c.name} className="rounded-2xl border bg-white p-4">
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex items-center gap-3">
                        <div className="rounded-xl bg-slate-100 p-2">
                          <Icon className="h-4 w-4 text-slate-700" />
                        </div>
                        <div>
                          <div className="font-medium">{c.name}</div>
                          <div className="text-xs text-slate-500">{c.detail}</div>
                        </div>
                      </div>
                      {statusBadge(c.status)}
                    </div>
                  </div>
                );
              })}
            </CardContent>
          </Card>
        </div>

        <Card className="rounded-2xl shadow-sm">
          <CardHeader>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <CardTitle>Evidence Register</CardTitle>
                <CardDescription>Filter by control family and hand auditors the exact artifact they asked for.</CardDescription>
              </div>
              <div className="flex flex-wrap gap-2">
                {['All', 'AC', 'IA', 'AU', 'CM', 'SI', 'IR'].map((f) => (
                  <Button
                    key={f}
                    variant={selectedFamily === f ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setSelectedFamily(f)}
                  >
                    {f}
                  </Button>
                ))}
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <div className="overflow-hidden rounded-2xl border bg-white">
              <table className="w-full text-left text-sm">
                <thead className="bg-slate-100 text-slate-600">
                  <tr>
                    <th className="px-4 py-3 font-medium">Control</th>
                    <th className="px-4 py-3 font-medium">Source</th>
                    <th className="px-4 py-3 font-medium">Artifact</th>
                    <th className="px-4 py-3 font-medium">Updated</th>
                    <th className="px-4 py-3 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEvidence.map((row, idx) => (
                    <tr key={idx} className="border-t">
                      <td className="px-4 py-3 font-medium">{row.control}</td>
                      <td className="px-4 py-3">{row.source}</td>
                      <td className="px-4 py-3">{row.artifact}</td>
                      <td className="px-4 py-3 text-slate-500">{row.updated}</td>
                      <td className="px-4 py-3">{statusBadge(row.status)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
