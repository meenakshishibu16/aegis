import type { Config, Scenario, ScenarioResult, Stats } from "./types";

export const API_URL: string = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
export const WS_URL = API_URL.replace(/^http/, "ws") + "/ws/events";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(API_URL + path, init);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail ?? `${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  config: () => request<Config>("/config"),
  scenarios: () => request<Scenario[]>("/scenarios"),
  stats: () => request<Stats>("/stats"),
  runScenario: (id: string, isProtected: boolean) =>
    request<ScenarioResult>(`/simulator/run/${id}?protected=${isProtected}`, { method: "POST" }),
};
