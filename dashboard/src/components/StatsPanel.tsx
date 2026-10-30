import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Stats } from "../types";

const pct = (v: number | null) => (v === null ? "-" : `${Math.round(v * 100)}%`);
const STAGES = ["inspect", "authorize", "egress"];

function Tile({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: "good" | "crit" }) {
  return (
    <div className="rounded border border-ink-700 bg-ink-950 p-3">
      <div className="text-xs text-ink-400">{label}</div>
      <div className="mt-1 flex items-center gap-2 text-2xl font-semibold text-ink-100">
        {tone && <span className={`h-2.5 w-2.5 rounded-full ${tone === "good" ? "bg-good" : "bg-crit"}`} aria-hidden />}
        {value}
      </div>
      {sub && <div className="mt-0.5 text-[11px] text-ink-400">{sub}</div>}
    </div>
  );
}

export default function StatsPanel({ stats }: { stats: Stats | null }) {
  if (!stats) return null;
  const stageData = STAGES.map((s) => ({ stage: s, count: stats.blocks_by_stage[s] ?? 0 }));
  const off = stats.attack_success_rate_off;
  const on = stats.attack_success_rate_on;

  return (
    <section className="panel p-4">
      <h2 className="mb-3 text-lg font-semibold">Stats</h2>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Tile label="Attack success, AEGIS OFF" value={pct(off)} sub={`${stats.attacks_run_off} attack runs`} tone={off ? "crit" : undefined} />
        <Tile label="Attack success, AEGIS ON" value={pct(on)} sub={`${stats.attacks_run_on} attack runs`} tone={on === 0 ? "good" : on ? "crit" : undefined} />
        <Tile label="False positive rate (benign)" value={pct(stats.false_positive_rate)} sub="benign control blocked" />
        <Tile label="Check latency p50" value={`${stats.latency_ms.inspect?.p50 ?? 0} ms`} sub="content inspection" />
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <div>
          <h3 className="mb-1 text-sm text-ink-300">Interventions by stage <span className="text-ink-400">(block, deny, sanitize)</span></h3>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={stageData} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                <CartesianGrid vertical={false} stroke="#383835" strokeDasharray="2 4" />
                <XAxis dataKey="stage" tick={{ fill: "#c3c2b7", fontSize: 12 }} axisLine={{ stroke: "#383835" }} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fill: "#9b9a92", fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip cursor={{ fill: "#26262480" }} contentStyle={{ background: "#1a1a19", border: "1px solid #383835", color: "#f0efec", fontSize: 12 }}
                  formatter={(v: number) => [v, "interventions"]} />
                <Bar dataKey="count" fill="#3987e5" radius={[4, 4, 0, 0]} maxBarSize={48} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div>
          <h3 className="mb-1 text-sm text-ink-300">AEGIS added latency per check</h3>
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-ink-400">
              <tr><th className="py-1 font-normal">Stage</th><th className="font-normal">p50</th><th className="font-normal">p95</th><th className="font-normal">checks</th></tr>
            </thead>
            <tbody>
              {STAGES.map((s) => {
                const l = stats.latency_ms[s];
                return (
                  <tr key={s} className="border-t border-ink-700">
                    <td className="py-1.5">{s}</td>
                    <td className="font-mono">{l ? `${l.p50} ms` : "-"}</td>
                    <td className="font-mono">{l ? `${l.p95} ms` : "-"}</td>
                    <td className="font-mono text-ink-400">{l?.n ?? 0}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <p className="mt-2 text-[11px] text-ink-400">Excludes agent LLM time. Inspect includes the DeBERTa classifier on CPU.</p>
        </div>
      </div>
    </section>
  );
}
