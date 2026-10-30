import { useEffect, useRef, useState } from "react";
import { WS_URL } from "../api";
import type { AegisEvent } from "../types";

type Filter = "all" | "blocked" | "allowed" | "agent";

const FILTERS: Record<Filter, (e: AegisEvent) => boolean> = {
  all: () => true,
  blocked: (e) => ["BLOCK", "DENY", "SANITIZE", "TAINT"].includes(e.decision),
  allowed: (e) => e.decision === "ALLOW",
  agent: (e) => e.stage === "agent",
};

const STYLE: Record<string, string> = {
  ALLOW: "border-l-good",
  BLOCK: "border-l-crit",
  DENY: "border-l-crit",
  SANITIZE: "border-l-warn",
  TAINT: "border-l-warn",
};
const BADGE: Record<string, string> = {
  ALLOW: "text-good",
  BLOCK: "text-crit",
  DENY: "text-crit",
  SANITIZE: "text-warn",
  TAINT: "text-warn",
};

export default function LiveFeed() {
  const [events, setEvents] = useState<AegisEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [filter, setFilter] = useState<Filter>("all");
  const retry = useRef<number>();

  useEffect(() => {
    let ws: WebSocket;
    let closed = false;
    const connect = () => {
      ws = new WebSocket(WS_URL);
      ws.onopen = () => setConnected(true);
      ws.onmessage = (m) => setEvents((prev) => [JSON.parse(m.data) as AegisEvent, ...prev].slice(0, 300));
      ws.onclose = () => {
        setConnected(false);
        if (!closed) retry.current = window.setTimeout(connect, 2000);
      };
    };
    connect();
    return () => {
      closed = true;
      window.clearTimeout(retry.current);
      ws?.close();
    };
  }, []);

  const shown = events.filter(FILTERS[filter]);

  return (
    <section className="panel flex max-h-[calc(100vh-6rem)] min-h-[400px] flex-col p-4 xl:sticky xl:top-4">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="text-lg font-semibold">Live Feed</h2>
        <span className={`text-xs ${connected ? "text-good" : "text-crit"}`}>{connected ? "● live" : "○ disconnected"}</span>
      </div>
      <div className="mb-3 flex gap-1 text-xs">
        {(Object.keys(FILTERS) as Filter[]).map((f) => (
          <button key={f} onClick={() => setFilter(f)}
            className={`rounded px-2 py-1 capitalize ${filter === f ? "bg-ink-700 text-ink-100" : "text-ink-400 hover:bg-ink-800"}`}>
            {f}
          </button>
        ))}
        <button onClick={() => setEvents([])} className="ml-auto rounded px-2 py-1 text-ink-400 hover:bg-ink-800">clear</button>
      </div>
      <ol className="flex min-h-0 flex-1 flex-col gap-1.5 overflow-y-auto pr-1">
        {shown.length === 0 && <li className="m-auto text-sm text-ink-400">Waiting for events… run a scenario.</li>}
        {shown.map((e) => (
          <li key={e.id} className={`rounded border border-ink-700 border-l-4 bg-ink-950 px-2 py-1.5 text-xs ${STYLE[e.decision] ?? "border-l-ink-700"}`}>
            <div className="flex items-center gap-2">
              <span className={`font-bold ${BADGE[e.decision] ?? "text-ink-300"}`}>{e.decision}</span>
              <span className="text-ink-400">{e.stage}</span>
              {e.tool_name && <span className="font-mono text-ink-300">{e.tool_name}</span>}
              {!e.protected && <span className="rounded bg-crit/20 px-1 text-[10px] text-crit">UNPROTECTED</span>}
              <span className="ml-auto text-[10px] text-ink-400">
                {e.latency_ms > 0 && `${e.latency_ms.toFixed(1)}ms · `}{new Date(e.timestamp).toLocaleTimeString()}
              </span>
            </div>
            {e.reasons.length > 0 && <div className="mt-0.5 text-ink-300">{e.reasons.join("; ")}</div>}
            {e.rule_ids.length > 0 && <div className="mt-0.5 font-mono text-[10px] text-ink-400">{e.rule_ids.join(" ")}</div>}
            {e.spans.length > 0 && (
              <div className="mt-1 break-words rounded bg-crit/10 px-1.5 py-0.5 font-mono text-[10px] text-crit">“{e.spans[0]}”</div>
            )}
            {!e.spans.length && e.args_excerpt && <div className="mt-0.5 break-all font-mono text-[10px] text-ink-400">{e.args_excerpt}</div>}
          </li>
        ))}
      </ol>
    </section>
  );
}
