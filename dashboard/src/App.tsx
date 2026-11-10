import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import type { Config, Stats } from "./types";
import AttackLab from "./components/AttackLab";
import LiveFeed from "./components/LiveFeed";
import Playground from "./components/Playground";
import StatsPanel from "./components/StatsPanel";

type Tab = "try" | "demos" | "activity" | "results";

const TABS: { id: Tab; label: string; hint: string }[] = [
  { id: "try", label: "Try it", hint: "Type any text and see if AEGIS flags it" },
  { id: "demos", label: "Attack demos", hint: "Ready-made attacks, run with and without AEGIS" },
  { id: "activity", label: "Activity log", hint: "Every check AEGIS made, live" },
  { id: "results", label: "Results", hint: "How many attacks AEGIS stopped" },
];

export default function App() {
  const [tab, setTab] = useState<Tab>("try");
  const [config, setConfig] = useState<Config | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refreshStats = useCallback(() => {
    api.stats().then(setStats).catch((e: Error) => setError(e.message));
  }, []);

  useEffect(() => {
    api.config().then(setConfig).catch(() => setError("Backend not reachable on http://localhost:8000. Start it with run_backend."));
    refreshStats();
  }, [refreshStats]);

  return (
    <div className="mx-auto max-w-5xl px-4 py-6 sm:px-6">
      <header className="mb-5 flex flex-wrap items-center gap-3">
        <span className="grid h-9 w-9 place-items-center rounded bg-accent font-bold text-white">A</span>
        <div>
          <h1 className="text-xl font-semibold tracking-wide">AEGIS</h1>
          <p className="text-sm text-ink-400">Stops AI assistants from being tricked by hidden instructions</p>
        </div>
        {config?.replay_mode && (
          <span className="ml-auto rounded border border-warn px-2 py-1 text-xs font-bold tracking-widest text-warn" title="LLM responses replayed from recorded cassettes">
            REPLAY
          </span>
        )}
      </header>

      <nav className="mb-4 flex gap-1 overflow-x-auto border-b border-ink-700">
        {TABS.map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`-mb-px whitespace-nowrap border-b-2 px-4 py-2 text-sm ${tab === t.id ? "border-accent text-ink-100" : "border-transparent text-ink-400 hover:text-ink-300"}`}>
            {t.label}
          </button>
        ))}
      </nav>
      <p className="mb-4 text-sm text-ink-400">{TABS.find((t) => t.id === tab)?.hint}</p>

      {error && <div className="panel mb-4 border-crit p-3 text-sm text-crit">{error}</div>}

      {tab === "try" && <Playground onRunFinished={refreshStats} />}
      {tab === "demos" && <AttackLab stats={stats} onRunFinished={refreshStats} />}
      {tab === "activity" && <LiveFeed />}
      {tab === "results" && <StatsPanel stats={stats} />}
    </div>
  );
}
