"""Benchmark the AEGIS detector on public prompt-injection datasets, with a layer ablation.

Every sample is scored once by the heuristics and once by the classifier; the three configurations
(rules only, classifier only, AEGIS = max of both, as in core/detector/pipeline.py) are derived from those scores.

Usage (from repo root, venv active; needs `pip install pyarrow` and network for the first download):
    python simulator/benchmark.py                       # all datasets, up to 500 samples each
    python simulator/benchmark.py --only bipia --limit 200
    python simulator/benchmark.py --no-classifier       # heuristics only, fast
"""

import argparse
import csv
import json
import random
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from aegis.config import RESULTS_DIR, settings  # noqa: E402
from aegis.core.detector import heuristics  # noqa: E402

SEED = 0


@dataclass
class Sample:
    text: str
    label: int  # 1 = injection, 0 = benign
    group: str


@dataclass
class DatasetInfo:
    name: str
    hf_id: str
    kind: str
    note: str
    load: Callable[[], list[Sample]]


def _download(repo: str, filename: str) -> Path:
    from huggingface_hub import hf_hub_download

    return Path(hf_hub_download(repo, filename, repo_type="dataset"))


def _parquet(repo: str, filename: str) -> list[dict]:
    import pyarrow.parquet as pq

    return pq.read_table(_download(repo, filename)).to_pylist()


def load_deepset() -> list[Sample]:
    rows = _parquet("deepset/prompt-injections", "data/test-00000-of-00001-701d16158af87368.parquet")
    return [Sample(r["text"], int(r["label"]), "injection" if r["label"] else "benign") for r in rows]


def load_safeguard() -> list[Sample]:
    rows = _parquet("xTRam1/safe-guard-prompt-injection", "data/test-00000-of-00001.parquet")
    return [Sample(r["text"], int(r["label"]), "injection" if r["label"] else "benign") for r in rows]


def load_jackhhao() -> list[Sample]:
    with _download("jackhhao/jailbreak-classification", "default/jailbreak_dataset_test.csv").open(encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    return [Sample(r["prompt"], int(r["type"] == "jailbreak"), r["type"]) for r in rows]


def load_bipia() -> list[Sample]:
    """Email and table contexts with an injected attack; the same context with the attack removed is the benign twin."""
    rows = [r for r in _parquet("geodesic-research/bipia", "bipia/train-00000-of-00001.parquet")
            if r["task_name"] in ("email", "table") and r["attack_str"] and r["attack_str"] in r["context"]]
    attacked = [Sample(r["context"], 1, f"{r['task_name']}/{r['attack_category']}/{r['position']}") for r in rows]
    clean: dict[str, Sample] = {}
    for r in rows:
        text = r["context"].replace(r["attack_str"], "").strip()
        clean.setdefault(text, Sample(text, 0, f"{r['task_name']}/clean"))
    return attacked + list(clean.values())


DATASETS = [
    DatasetInfo("deepset", "deepset/prompt-injections", "direct", "English + German", load_deepset),
    DatasetInfo("safe-guard", "xTRam1/safe-guard-prompt-injection", "direct", "", load_safeguard),
    DatasetInfo("jackhhao", "jackhhao/jailbreak-classification", "jailbreak", "SEEN IN CLASSIFIER TRAINING: scores are inflated", load_jackhhao),
    DatasetInfo("bipia", "geodesic-research/bipia", "indirect", "injections hidden in emails / tables", load_bipia),
]


def balanced_sample(samples: list[Sample], limit: int) -> list[Sample]:
    """Up to limit/2 per class, so a skewed dataset doesn't hide a weak detection rate."""
    rng = random.Random(SEED)
    out: list[Sample] = []
    for label in (1, 0):
        pool = [s for s in samples if s.label == label]
        rng.shuffle(pool)
        out += pool[: limit // 2]
    return out


def metrics(labels: list[int], scores: list[float], threshold: float) -> dict[str, float | None]:
    tp = sum(1 for y, s in zip(labels, scores) if y and s >= threshold)
    fp = sum(1 for y, s in zip(labels, scores) if not y and s >= threshold)
    pos = sum(labels)
    neg = len(labels) - pos
    recall = tp / pos if pos else None
    precision = tp / (tp + fp) if tp + fp else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else 0.0
    return {"detection_rate": recall, "false_alarm_rate": fp / neg if neg else None, "precision": precision, "f1": f1}


def auc(labels: list[int], scores: list[float]) -> float | None:
    """ROC AUC as the probability a random attack scores above a random benign sample (ties count half)."""
    pos = [s for y, s in zip(labels, scores) if y]
    neg = [s for y, s in zip(labels, scores) if not y]
    if not pos or not neg:
        return None
    wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def score_all(samples: list[Sample], classifier) -> list[dict]:
    out = []
    for i, s in enumerate(samples, 1):
        start = time.perf_counter()
        rules = heuristics.combined_score(heuristics.scan(s.text))
        clf = classifier.score(s.text).score if classifier else 0.0
        out.append({**asdict(s), "rules": round(rules, 4), "classifier": round(clf, 4), "aegis": round(max(rules, clf), 4),
                    "ms": round((time.perf_counter() - start) * 1000, 1)})
        if i % 100 == 0:
            print(f"  {i}/{len(samples)}", flush=True)
    return out


def summarize(scored: list[dict], use_classifier: bool) -> dict:
    labels = [r["label"] for r in scored]
    configs = ["rules", "classifier", "aegis"] if use_classifier else ["rules"]
    return {
        "n_attack": sum(labels),
        "n_benign": len(labels) - sum(labels),
        "configs": {
            c: {
                "flag": metrics(labels, [r[c] for r in scored], settings.sanitize_threshold),
                "block": metrics(labels, [r[c] for r in scored], settings.block_threshold),
                "auc": auc(labels, [r[c] for r in scored]),
            }
            for c in configs
        },
        "by_group": {
            g: {"n": len(rows), "flagged": sum(r["aegis"] >= settings.sanitize_threshold for r in rows) / len(rows)}
            for g in sorted({r["group"] for r in scored})
            for rows in [[r for r in scored if r["group"] == g]]
        },
        "median_ms": sorted(r["ms"] for r in scored)[len(scored) // 2],
    }


def pct(v: float | None) -> str:
    return "-" if v is None else f"{v * 100:.1f}%"


def report(results: dict) -> str:
    lines = [
        "# AEGIS detector benchmark",
        "",
        f"Generated {results['generated']}. Classifier: `{results['classifier'] or 'disabled'}`. "
        f"Flag = score ≥ {settings.sanitize_threshold} (SANITIZE or BLOCK); block = score ≥ {settings.block_threshold}.",
        "Samples are class-balanced per dataset (seed 0). Detection rate = attacks flagged; false alarms = benign samples flagged.",
        "",
        "| dataset | type | attacks / benign | config | detection rate | false alarms | precision | F1 | blocked (≥0.85) | AUC |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name, d in results["datasets"].items():
        for c, m in d["configs"].items():
            lines.append(
                f"| {name} | {d['kind']} | {d['n_attack']} / {d['n_benign']} | {c} | {pct(m['flag']['detection_rate'])} | "
                f"{pct(m['flag']['false_alarm_rate'])} | {pct(m['flag']['precision'])} | {m['flag']['f1']:.3f} | "
                f"{pct(m['block']['detection_rate'])} | {'-' if m['auc'] is None else f'{m['auc']:.3f}'} |")
    lines.append("")
    for name, d in results["datasets"].items():
        if d["note"]:
            lines.append(f"- **{name}**: {d['note']}")
    for name, d in results["datasets"].items():
        lines += ["", f"## {name}: flag rate by group (AEGIS)", "", "| group | n | flagged |", "|---|---|---|"]
        lines += [f"| {g} | {v['n']} | {pct(v['flagged'])} |" for g, v in d["by_group"].items()]
        lines += ["", "Hardest missed attacks:", ""]
        lines += [f"- `{r['aegis']:.2f}` {r['text'][:160].replace(chr(10), ' ')!r}" for r in d["missed"]]
        lines += ["", "Worst false alarms:", ""]
        lines += [f"- `{r['aegis']:.2f}` {r['text'][:160].replace(chr(10), ' ')!r}" for r in d["false_alarms"]] or ["- none"]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", nargs="*", choices=[d.name for d in DATASETS])
    parser.add_argument("--limit", type=int, default=500, help="max samples per dataset (half attacks, half benign)")
    parser.add_argument("--no-classifier", action="store_true")
    args = parser.parse_args()

    classifier = None
    if not args.no_classifier:
        from aegis.core.detector.classifier import get_classifier

        classifier = get_classifier()
        classifier.score("warm-up: load the classifier before timing anything")

    results: dict = {"generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                     "classifier": None if args.no_classifier else settings.classifier_model, "datasets": {}}
    all_scored: dict[str, list[dict]] = {}
    for info in DATASETS:
        if args.only and info.name not in args.only:
            continue
        print(f"> {info.name} ({info.hf_id})", flush=True)
        samples = balanced_sample(info.load(), args.limit)
        scored = score_all(samples, classifier)
        all_scored[info.name] = scored
        flag = settings.sanitize_threshold
        results["datasets"][info.name] = {
            "hf_id": info.hf_id, "kind": info.kind, "note": info.note, **summarize(scored, classifier is not None),
            "missed": sorted((r for r in scored if r["label"] and r["aegis"] < flag), key=lambda r: r["aegis"])[:5],
            "false_alarms": sorted((r for r in scored if not r["label"] and r["aegis"] >= flag), key=lambda r: -r["aegis"])[:5],
        }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "benchmark.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (RESULTS_DIR / "benchmark_scores.json").write_text(json.dumps(all_scored), encoding="utf-8")
    md = report(results)
    (RESULTS_DIR / "benchmark.md").write_text(md, encoding="utf-8")
    print("\n" + md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
