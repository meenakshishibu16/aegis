import { useEffect, useState } from "react";
import { api } from "../api";
import type { Scenario, ScenarioResult, Stats, Step } from "../types";

type Side = "off" | "on";
type Results = Record<string, Partial<Record<Side, ScenarioResult>>>;

export default function AttackLab({ stats, onRunFinished }: { stats: Stats | null; onRunFinished: () => void }) {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [results, setResults] = useState<Results>({});
  const [running, setRunning] = useState<Partial<Record<Side, boolean>>>({});
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.scenarios().then((s) => {
      setScenarios(s);
      setSelected((cur) => cur || s[0]?.id || "");
    }).catch(() => undefined);
  }, []);

  // Seed panels with the latest stored run of each scenario.
  useEffect(() => {
    if (!stats) return;
    setResults((prev) => {
      const next: Results = { ...prev };
      for (const r of stats.scenario_runs) {
        const side: Side = r.protected ? "on" : "off";
        next[r.scenario_id] = { ...next[r.scenario_id], [side]: next[r.scenario_id]?.[side] ?? r };
      }
      return next;
    });
  }, [stats]);

  const scenario = scenarios.find((s) => s.id === selected);

  async function run(side: Side) {
    if (!scenario) return;
    setRunning((r) => ({ ...r, [side]: true }));
    setError(null);
    try {
      const res = await api.runScenario(scenario.id, side === "on");
      setResults((prev) => ({ ...prev, [scenario.id]: { ...prev[scenario.id], [side]: res } }));
      onRunFinished();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunning((r) => ({ ...r, [side]: false }));
    }
  }

  async function runBoth() {
    await run("off");
    await run("on");
  }

  const busy = Boolean(running.off || running.on);

  return (
    <section className="panel p-4">
      <div className="mb-3 flex items-baseline justify-between">
        <h2 className="text-lg font-semibold">Attack Lab</h2>
        <span className="text-xs text-ink-400">Same task, same model: without AEGIS vs with AEGIS</span>
      </div>

      <div className="grid gap-4 lg:grid-cols-[260px_minmax(0,1fr)]">
        <ul className="flex flex-col gap-1">
          {scenarios.map((s) => {
            const r = results[s.id];
            return (
              <li key={s.id}>
                <button
                  onClick={() => setSelected(s.id)}
                  className={`w-full rounded px-3 py-2 text-left text-sm transition ${s.id === selected ? "bg-ink-700" : "hover:bg-ink-800"}`}
                >
                  <div className="flex items-center gap-2">
                    <span className={`rounded px-1.5 text-[10px] font-bold uppercase ${s.kind === "attack" ? "bg-crit/20 text-crit" : "bg-good/20 text-good"}`}>
                      {s.kind}
                    </span>
                    <span className="truncate">{s.name}</span>
                  </div>
                  <div className="mt-1 flex gap-2 text-[11px] text-ink-400">
                    <span>OFF: {r?.off ? outcomeShort(r.off) : "-"}</span>
                    <span>ON: {r?.on ? outcomeShort(r.on) : "-"}</span>
                  </div>
                </button>
              </li>
            );
          })}
        </ul>

        {scenario && (
          <div className="min-w-0">
            <p className="text-sm text-ink-300">{scenario.description}</p>
            <div className="mt-2 rounded border border-ink-700 bg-ink-950 p-2 font-mono text-xs text-ink-300">
              <span className="text-ink-400">user task › </span>{scenario.user_task}
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              <button disabled={busy} onClick={() => run("off")} className="btn border-crit text-crit">Run without AEGIS</button>
              <button disabled={busy} onClick={() => run("on")} className="btn border-good text-good">Run with AEGIS</button>
              <button disabled={busy} onClick={runBoth} className="btn border-accent text-accent">Run both</button>
            </div>
            {error && <p className="mt-2 text-sm text-crit">{error}</p>}

            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <ResultPanel title="AEGIS OFF" scenario={scenario} result={results[scenario.id]?.off} running={running.off} />
              <ResultPanel title="AEGIS ON" scenario={scenario} result={results[scenario.id]?.on} running={running.on} />
            </div>
          </div>
        )}
      </div>
      <style>{`.btn{border-width:1px;border-radius:.375rem;padding:.375rem .75rem;font-size:.875rem}.btn:hover:not(:disabled){background:#262624}.btn:disabled{opacity:.4;cursor:not-allowed}`}</style>
    </section>
  );
}

function outcomeShort(r: ScenarioResult): string {
  if (r.kind === "attack") return r.condition_met ? "compromised" : "safe";
  return r.condition_met ? "done" : "failed";
}

function headline(r: ScenarioResult): { text: string; tone: "good" | "crit" | "warn" } {
  if (r.kind === "attack") {
    return r.condition_met ? { text: "✕ ATTACK SUCCEEDED", tone: "crit" } : { text: "✓ ATTACK STOPPED", tone: "good" };
  }
  if (!r.condition_met) return { text: "✕ TASK NOT COMPLETED", tone: "crit" };
  return r.aegis_decision === "BLOCKED" ? { text: "! COMPLETED WITH BLOCKS", tone: "warn" } : { text: "✓ TASK COMPLETED", tone: "good" };
}

const TONE = { good: "border-good text-good", crit: "border-crit text-crit", warn: "border-warn text-warn" };
const VERDICT_STYLE: Record<Step["verdict"], string> = {
  EXECUTED: "text-ink-300",
  DENIED: "text-crit",
  BLOCKED: "text-crit",
  SANITIZED: "text-warn",
};

function ResultPanel({ title, scenario, result, running }: { title: string; scenario: Scenario; result?: ScenarioResult; running?: boolean }) {
  return (
    <div className="flex min-h-[220px] min-w-0 flex-col rounded border border-ink-700 bg-ink-950 p-3">
      <div className="mb-2 flex items-center justify-between text-xs uppercase tracking-widest text-ink-400">
        <span>{title}</span>
        {result?.replay && <span className="rounded border border-warn px-1.5 text-[10px] font-bold text-warn">REPLAY</span>}
      </div>
      {running ? (
        <div className="m-auto animate-pulse text-sm text-ink-400">Agent running… (CPU inference can take a minute)</div>
      ) : !result ? (
        <div className="m-auto text-sm text-ink-400">Not run yet</div>
      ) : (
        <ResultBody scenario={scenario} result={result} />
      )}
    </div>
  );
}

function ResultBody({ result }: { scenario: Scenario; result: ScenarioResult }) {
  const h = headline(result);
  return (
    <div className="flex min-w-0 flex-col gap-2 text-sm">
      <div className={`rounded border px-2 py-1.5 text-center font-bold tracking-wide ${TONE[h.tone]}`}>{h.text}</div>
      {result.protected && (
        <dl className="grid grid-cols-[90px_minmax(0,1fr)] gap-x-2 gap-y-0.5 text-xs">
          <dt className="text-ink-400">Decision</dt><dd>{result.aegis_decision}</dd>
          <dt className="text-ink-400">Caught at</dt><dd>{result.caught_stage ?? "-"}</dd>
          <dt className="text-ink-400">Rule</dt><dd className="break-all font-mono">{result.caught_rules.join(", ") || "-"}</dd>
          <dt className="text-ink-400">Why</dt><dd className="text-ink-300">{result.reasons.join("; ") || "-"}</dd>
          <dt className="text-ink-400">AEGIS time</dt><dd>{result.aegis_latency_ms.toFixed(0)} ms</dd>
        </dl>
      )}
      {result.steps && result.steps.length > 0 && (
        <ol className="mt-1 flex flex-col gap-1 border-t border-ink-700 pt-2 font-mono text-[11px]">
          {result.steps.map((s, i) => (
            <li key={i} className="min-w-0">
              <span className="text-ink-400">#{s.step} </span>
              {s.tool ? (
                <>
                  <span>{s.tool}</span>
                  <span className="text-ink-400">({truncate(JSON.stringify(s.args ?? {}), 80)})</span>{" "}
                  <span className={VERDICT_STYLE[s.verdict]}>{s.verdict}</span>
                </>
              ) : (
                <span className={VERDICT_STYLE[s.verdict]}>{s.kind === "final" ? "final answer" : s.kind} {s.verdict !== "EXECUTED" && s.verdict}</span>
              )}
            </li>
          ))}
        </ol>
      )}
      <div className="mt-1 border-t border-ink-700 pt-2 text-xs text-ink-300">
        <div className="mb-0.5 text-ink-400">Final answer</div>
        <p className="line-clamp-4 whitespace-pre-wrap break-words">{result.final_answer || "-"}</p>
      </div>
      <div className="text-right text-[10px] text-ink-400">{result.duration_s}s · session {result.session_id}</div>
    </div>
  );
}

function truncate(s: string, n: number) {
  return s.length > n ? s.slice(0, n) + "…" : s;
}
