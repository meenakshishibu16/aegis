export type Decision = "ALLOW" | "SANITIZE" | "BLOCK" | "DENY" | "START" | "TOOL" | "TAINT" | "FINAL";

export interface AegisEvent {
  id: string;
  session_id: string;
  timestamp: string;
  stage: "inspect" | "authorize" | "egress" | "agent";
  decision: Decision;
  risk_score: number;
  reasons: string[];
  rule_ids: string[];
  tool_name: string | null;
  args_excerpt: string | null;
  content_excerpt: string | null;
  spans: string[];
  latency_ms: number;
  step: number;
  protected: boolean;
  scenario_id: string | null;
}

export interface Scenario {
  id: string;
  name: string;
  description: string;
  kind: "attack" | "benign";
  user_task: string;
  attack_vector: string;
  expected_aegis_outcome: "blocked" | "allowed";
}

export interface Step {
  step: number;
  kind: string;
  tool: string | null;
  args: Record<string, unknown> | null;
  output: string;
  verdict: "EXECUTED" | "DENIED" | "BLOCKED" | "SANITIZED";
  reasons: string[];
}

export interface ScenarioResult {
  scenario_id: string;
  name: string;
  kind: "attack" | "benign";
  protected: boolean;
  condition_met: boolean;
  outcome_ok: boolean;
  aegis_decision: "OFF" | "BLOCKED" | "SANITIZED" | "ALLOWED";
  caught_stage: string | null;
  caught_rules: string[];
  reasons: string[];
  aegis_latency_ms: number;
  duration_s: number;
  session_id: string;
  replay: boolean;
  final_answer: string;
  steps?: Step[];
}

export interface Stats {
  attack_success_rate_off: number | null;
  attack_success_rate_on: number | null;
  attacks_run_off: number;
  attacks_run_on: number;
  false_positive_rate: number | null;
  blocks_by_stage: Record<string, number>;
  latency_ms: Record<string, { p50: number; p95: number; n: number }>;
  scenario_runs: ScenarioResult[];
}

export interface Config {
  replay_mode: boolean;
  agent_model: string;
  classifier_model: string | null;
}

export interface InspectResult {
  score: number;
  label: "benign" | "suspicious" | "injection";
  action: "ALLOW" | "SANITIZE" | "BLOCK";
  triggered_layers: string[];
  spans: string[];
  reasons: string[];
  rule_ids: string[];
  latency_ms: number;
  sanitized_text: string;
}

export interface AgentRunResult {
  session_id: string;
  task: string;
  protected: boolean;
  final_answer: string;
  steps: Step[];
  tainted_at_step: number | null;
  aegis_latency_ms: number;
  duration_s: number;
}
