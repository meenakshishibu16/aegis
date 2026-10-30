import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import type { Config, Stats } from "./types";
import AttackLab from "./components/AttackLab";
import LiveFeed from "./components/LiveFeed";
import StatsPanel from "./components/StatsPanel";

export default function App() {
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
    <div className="mx-auto max-w-[1500px] px-4 py-4 sm:px-6">
      <header className="mb-4 flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2">
          <span className="grid h-8 w-8 place-items-center rounded bg-accent font-bold text-white">A</span>
          <h1 className="text-xl font-semibold tracking-wide">AEGIS</h1>
          <span className="text-sm text-ink-400">Runtime security for agentic AI</span>
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-2 text-xs">
          {config?.replay_mode && (
            <span className="rounded border border-warn px-2 py-1 font-bold tracking-widest text-warn" title="LLM responses replayed from recorded cassettes">
              ● REPLAY
            </span>
          )}
          {config && (
            <span className="rounded border border-ink-700 px-2 py-1 font-mono text-ink-300">
              agent: {config.agent_model} · detector: {config.classifier_model ? "heuristics + classifier" : "heuristics"}
            </span>
          )}
        </div>
      </header>

      {error && <div className="panel mb-4 border-crit p-3 text-sm text-crit">{error}</div>}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
        <div className="flex min-w-0 flex-col gap-4">
          <AttackLab stats={stats} onRunFinished={refreshStats} />
          <StatsPanel stats={stats} />
        </div>
        <LiveFeed />
      </div>
    </div>
  );
}
