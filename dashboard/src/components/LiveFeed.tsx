import { useEffect, useRef, useState } from "react";
import { api, WS_URL } from "../api";
import type { AegisEvent } from "../types";

type Filter = "everything" | "only problems";

const FILTERS: Record<Filter, (e: AegisEvent) => boolean> = {
  everything: () => true,
  "only problems": (e) => ["BLOCK", "DENY", "SANITIZE", "TAINT"].includes(e.decision),
};

const STAGE_LABEL: Record<AegisEvent["stage"], string> = {
  inspect: "Checked incoming text",
  authorize: "Checked an action",
  egress: "Checked outgoing data",
  agent: "Assistant",
};
const DECISION_LABEL: Record<string, string> = {
  ALLOW: "Allowed",
  BLOCK: "Blocked",
  DENY: "Stopped",
  SANITIZE: "Cleaned",
  TAINT: "Marked untrusted",
  START: "Started",
  TOOL: "Used a tool",
  FINAL: "Finished",
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
  const [filter, setFilter] = useState<Filter>("everything");
  const retry = useRef<number>();

  // Backfill recent history so the feed isn't empty on load; live events are merged on top.
  useEffect(() => {
    api.recentEvents().then((history) =>
      setEvents((live) => {
        const ids = new Set(live.map((e) => e.id));
        return [...live, ...history.filter((e) => !ids.has(e.id))].slice(0, 300);
      }),
    ).catch(() => undefined);
  }, []);

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
    <section className="panel flex max-h-[calc(100vh-12rem)] min-h-[400px] flex-col p-5">
      <div className="mb-3 flex items-center gap-1 text-sm">
        {(Object.keys(FILTERS) as Filter[]).map((f) => (
          <button key={f} onClick={() => setFilter(f)}
            className={`rounded px-3 py-1 capitalize ${filter === f ? "bg-ink-700 text-ink-100" : "text-ink-400 hover:bg-ink-800"}`}>
            {f}
          </button>
        ))}
        <span className={`ml-auto text-xs ${connected ? "text-good" : "text-crit"}`}>{connected ? "● live" : "○ disconnected"}</span>
        <button onClick={() => setEvents([])} className="rounded px-2 py-1 text-ink-400 hover:bg-ink-800">clear</button>
      </div>
      <ol className="flex min-h-0 flex-1 flex-col gap-1.5 overflow-y-auto pr-1">
        {shown.length === 0 && <li className="m-auto text-sm text-ink-400">Nothing yet. Check some text or run a demo.</li>}
        {shown.map((e) => (
          <li key={e.id} className={`rounded border border-ink-700 border-l-4 bg-ink-950 px-3 py-2 text-sm ${STYLE[e.decision] ?? "border-l-ink-700"}`}>
            <div className="flex items-center gap-2">
              <span className={`font-semibold ${BADGE[e.decision] ?? "text-ink-300"}`}>{DECISION_LABEL[e.decision] ?? e.decision}</span>
              <span className="text-ink-400">· {STAGE_LABEL[e.stage]}</span>
              {e.tool_name && <span className="font-mono text-xs text-ink-300">{e.tool_name}</span>}
              {!e.protected && <span className="rounded bg-crit/20 px-1 text-[10px] text-crit">AEGIS OFF</span>}
              <span className="ml-auto text-[10px] text-ink-400">{new Date(e.timestamp).toLocaleTimeString()}</span>
            </div>
            {e.reasons.length > 0 && <div className="mt-0.5 text-xs text-ink-300">{e.reasons.join("; ")}</div>}
            {e.spans.length > 0 && (
              <div className="mt-1 break-words rounded bg-crit/10 px-1.5 py-0.5 text-xs text-crit">“{e.spans[0]}”</div>
            )}
          </li>
        ))}
      </ol>
    </section>
  );
}
