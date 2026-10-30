"""Run every scenario with AEGIS OFF and ON and print a results table.

Usage (from repo root, venv active):
    python simulator/runner.py                # live Ollama
    python simulator/runner.py --record       # live, and save cassettes for runs that behaved as expected
    python simulator/runner.py --replay       # deterministic replay from cassettes
    python simulator/runner.py --only s2_hidden_webpage
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from aegis.config import RESULTS_DIR  # noqa: E402
from aegis.core.events import bus  # noqa: E402
from aegis.core.gateway import default_gateway  # noqa: E402
from aegis.simulator import load_scenarios, run_scenario  # noqa: E402
from aegis.storage.db import Store  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", action="store_true")
    parser.add_argument("--replay", action="store_true")
    parser.add_argument("--only", nargs="*", help="scenario ids to run")
    parser.add_argument("--mode", choices=["both", "off", "on"], default="both")
    args = parser.parse_args()

    store = Store()
    bus.subscribe(store.save_event)
    gateway = default_gateway()
    modes = {"both": [False, True], "off": [False], "on": [True]}[args.mode]

    results = []
    for scenario in load_scenarios():
        if args.only and scenario.id not in args.only:
            continue
        for protected in modes:
            label = "ON " if protected else "OFF"
            print(f"> {scenario.id} [AEGIS {label}] ...", flush=True)
            result, run = run_scenario(scenario, protected, gateway, record=args.record, replay=args.replay)
            now = datetime.now(timezone.utc)
            store.save_session(run.session_id, scenario.user_task, protected, scenario.id, now, run.to_dict())
            store.save_scenario_run(scenario.id, protected, now, result.to_dict())
            results.append(result.to_dict())
            print(f"  condition_met={result.condition_met} decision={result.aegis_decision} stage={result.caught_stage} "
                  f"rules={result.caught_rules} ({result.duration_s}s)", flush=True)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "latest.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print_table(results)
    return 0


def print_table(results: list[dict]) -> None:
    header = f"| {'scenario':<26} | {'kind':<6} | {'AEGIS':<4} | {'attack ok / task done':<21} | {'decision':<9} | {'caught at':<9} | {'rule':<28} | {'AEGIS ms':>8} | {'as expected':<11} |"
    print("\n" + header)
    print("|" + "|".join("-" * (len(c)) for c in header.split("|")[1:-1]) + "|")
    for r in results:
        rule = ",".join(r["caught_rules"])[:28]
        print(f"| {r['scenario_id']:<26} | {r['kind']:<6} | {'ON' if r['protected'] else 'OFF':<4} | "
              f"{('YES' if r['condition_met'] else 'no'):<21} | {r['aegis_decision']:<9} | {str(r['caught_stage'] or '-'):<9} | "
              f"{rule or '-':<28} | {r['aegis_latency_ms']:>8.1f} | {('yes' if r['outcome_ok'] else 'NO'):<11} |")

    attacks_off = [r for r in results if r["kind"] == "attack" and not r["protected"]]
    attacks_on = [r for r in results if r["kind"] == "attack" and r["protected"]]
    if attacks_off:
        print(f"\nAttacks succeeded with AEGIS OFF: {sum(r['condition_met'] for r in attacks_off)}/{len(attacks_off)}")
    if attacks_on:
        print(f"Attacks succeeded with AEGIS ON:  {sum(r['condition_met'] for r in attacks_on)}/{len(attacks_on)}")
    for r in results:
        if r["kind"] == "benign" and r["protected"]:
            print(f"Benign control with AEGIS ON: completed={r['condition_met']}, blocked={r['aegis_decision'] == 'BLOCKED'}")


if __name__ == "__main__":
    raise SystemExit(main())
