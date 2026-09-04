from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path


def load_corpus_manifest(path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema") != "vulcanary.corpus-manifest.v1":
        raise ValueError("unsupported corpus manifest schema")
    corpora = document.get("corpora")
    if not isinstance(corpora, list) or not corpora:
        raise ValueError("corpus manifest must contain at least one corpus")
    identifiers: set[str] = set()
    for corpus in corpora:
        identifier = corpus.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            raise ValueError("corpus identifiers must be non-empty and unique")
        identifiers.add(identifier)
        if corpus.get("execution") != "never":
            raise ValueError(f"corpus {identifier} must prohibit execution")
        if corpus.get("source") == "git" and not re.fullmatch(r"[0-9a-f]{40}", str(corpus.get("revision", ""))):
            raise ValueError(f"git corpus {identifier} must pin a full commit SHA")
    return document


def _metrics(report: dict) -> dict[str, int | float]:
    benchmark = report.get("benchmark", {})
    return {
        "exposures": len(report.get("exposures", [])),
        "gaps": int(report.get("unmodeled_construct_count", len(report.get("unmodeled_constructs", [])))),
        "truncations": len(report.get("analysis_truncations", [])),
        "parse_errors": int(report.get("parse_errors", 0)),
        "analyzed_modules": int(report.get("analyzed_modules", 0)),
        "analyzed_calls": int(report.get("analyzed_calls", 0)),
        "true_positives": int(benchmark.get("true_positives", 0)),
        "false_positives": int(benchmark.get("false_positives", 0)),
        "false_negatives": int(benchmark.get("false_negatives", 0)),
        "true_negatives": int(benchmark.get("true_negatives", 0)),
        "recall": float(benchmark.get("recall", 0.0)),
        "precision": float(benchmark.get("precision", 0.0)),
        "false_positive_rate": float(benchmark.get("false_positive_rate", 0.0)),
        "benchmark_score": float(benchmark.get("benchmark_score", 0.0)),
        "elapsed_seconds": float(report.get("elapsed_seconds", 0.0)),
        "peak_memory_mb": float(report.get("peak_memory_mb", 0.0)),
    }


def _gap_categories(report: dict) -> dict[str, int]:
    return dict(sorted(Counter(str(item.get("category", "unclassified")) for item in report.get("unmodeled_constructs", [])).items()))


def _sink_identity(exposure: dict) -> tuple[str, str, int, str]:
    return (
        str(exposure.get("rule_id", "")), str(exposure.get("path", "")),
        int(exposure.get("line", 0)), str(exposure.get("sink", "")),
    )


def compare_corpus_reports(baseline: dict, candidate: dict) -> dict:
    baseline_metrics = _metrics(baseline)
    candidate_metrics = _metrics(candidate)
    baseline_fingerprints = {str(item["fingerprint"]) for item in baseline.get("exposures", []) if item.get("fingerprint")}
    candidate_fingerprints = {str(item["fingerprint"]) for item in candidate.get("exposures", []) if item.get("fingerprint")}
    baseline_by_sink = {_sink_identity(item): str(item.get("fingerprint", "")) for item in baseline.get("exposures", [])}
    candidate_by_sink = {_sink_identity(item): str(item.get("fingerprint", "")) for item in candidate.get("exposures", [])}
    churn = [
        {"rule_id": key[0], "path": key[1], "line": key[2], "sink": key[3], "before": baseline_by_sink[key], "after": candidate_by_sink[key]}
        for key in sorted(baseline_by_sink.keys() & candidate_by_sink.keys())
        if baseline_by_sink[key] != candidate_by_sink[key]
    ]
    baseline_categories = _gap_categories(baseline)
    candidate_categories = _gap_categories(candidate)
    return {
        "schema": "vulcanary.corpus-comparison.v1",
        "baseline": baseline_metrics,
        "candidate": candidate_metrics,
        "delta": {key: candidate_metrics[key] - baseline_metrics[key] for key in baseline_metrics},
        "gap_categories": {
            "baseline": baseline_categories,
            "candidate": candidate_categories,
            "delta": {
                key: candidate_categories.get(key, 0) - baseline_categories.get(key, 0)
                for key in sorted(baseline_categories.keys() | candidate_categories.keys())
            },
        },
        "fingerprints": {
            "added": sorted(candidate_fingerprints - baseline_fingerprints),
            "removed": sorted(baseline_fingerprints - candidate_fingerprints),
            "churn": churn,
        },
        "limits": {
            "baseline": baseline.get("analysis_limits", []),
            "candidate": candidate.get("analysis_limits", []),
        },
    }


def write_comparison(baseline_path: Path, candidate_path: Path, destination: Path) -> None:
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    destination.write_text(json.dumps(compare_corpus_reports(baseline, candidate), indent=2) + "\n", encoding="utf-8")
