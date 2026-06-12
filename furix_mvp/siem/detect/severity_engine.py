"""
severity_engine.py
------------------
Layer 4: Severity classification + structured anomaly report.

Takes fused scores, rule trigger lists, and the original ECS events
and produces a ranked, human-readable anomaly report using Rich.
No LLM involved anywhere.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import numpy as np

from ..config import (
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
)
from ..ingest import get_field

# FEATURE_NAMES comes from the ML feature module (Module 7), which may not be
# ported yet. Degrade gracefully: top-deviating-feature naming is purely
# explanatory, and _top_features() already returns [] when the length doesn't
# match. Once furix_mvp/siem/ml/layer2_features.py lands, this picks it up.
try:
    from ..ml.layer2_features import FEATURE_NAMES
except Exception:
    FEATURE_NAMES: List[str] = []


# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #

@dataclass
class AnomalyResult:
    index:          int
    fused_score:    float
    severity:       str                    # CRITICAL / HIGH / MEDIUM / LOW / NORMAL
    triggered_rules: List[str]
    event:          Dict[str, Any]
    feature_vector: np.ndarray = field(default_factory=lambda: np.array([]))
    top_features:   List[str]  = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Severity Engine
# --------------------------------------------------------------------------- #

class SeverityEngine:

    def __init__(self):
        self._baseline_means: Optional[np.ndarray] = None
        self._baseline_stds:  Optional[np.ndarray] = None

    def set_baseline_stats(self, means: np.ndarray, stds: np.ndarray):
        self._baseline_means = means
        self._baseline_stds  = stds

    # ------------------------------------------------------------------ #
    # Classify
    # ------------------------------------------------------------------ #

    @staticmethod
    def classify(score: float) -> str:
        if score >= SEVERITY_CRITICAL:
            return "CRITICAL"
        if score >= SEVERITY_HIGH:
            return "HIGH"
        if score >= SEVERITY_MEDIUM:
            return "MEDIUM"
        if score >= SEVERITY_LOW:
            return "LOW"
        return "NORMAL"

    # ------------------------------------------------------------------ #
    # Top deviating features
    # ------------------------------------------------------------------ #

    def _top_features(
        self,
        vec: np.ndarray,
        n: int = 3,
    ) -> List[str]:
        """Return the feature names with highest z-score deviation."""
        if self._baseline_means is None or len(vec) != len(FEATURE_NAMES):
            return []
        stds = np.where(
            self._baseline_stds == 0,
            1e-9,
            self._baseline_stds,
        )
        z = np.abs((vec - self._baseline_means) / stds)
        top_idx = np.argsort(z)[::-1][:n]
        return [FEATURE_NAMES[i] for i in top_idx]

    # ------------------------------------------------------------------ #
    # Build results list
    # ------------------------------------------------------------------ #

    def build_results(
        self,
        events:         List[Dict[str, Any]],
        fused_scores:   np.ndarray,
        rule_results:   List[tuple],           # (score, [rule_names])
        feature_matrix: np.ndarray,
        threshold:      str = "LOW",
    ) -> List[AnomalyResult]:
        """
        Filter events at or above threshold severity.
        Returns sorted list (highest score first).
        """
        min_score = {
            "CRITICAL": SEVERITY_CRITICAL,
            "HIGH":     SEVERITY_HIGH,
            "MEDIUM":   SEVERITY_MEDIUM,
            "LOW":      SEVERITY_LOW,
        }.get(threshold.upper(), SEVERITY_LOW)

        results: List[AnomalyResult] = []

        for i, (ev, score) in enumerate(zip(events, fused_scores)):
            if score < min_score:
                continue
            severity = self.classify(score)
            if severity == "NORMAL":
                continue

            _, triggered = rule_results[i]
            vec = feature_matrix[i] if i < len(feature_matrix) else np.array([])
            top = self._top_features(vec)

            results.append(AnomalyResult(
                index=i,
                fused_score=float(score),
                severity=severity,
                triggered_rules=triggered,
                event=ev,
                feature_vector=vec,
                top_features=top,
            ))

        results.sort(key=lambda r: r.fused_score, reverse=True)
        return results

    # ------------------------------------------------------------------ #
    # Save report to JSON file
    # ------------------------------------------------------------------ #

    def save_report(self, results: List[AnomalyResult], output_path: str):
        """
        Save the anomaly results to a structured JSON file.

        Output format:
        {
          "generated_at": "<ISO timestamp>",
          "total_findings": N,
          "summary": { "CRITICAL": n, "HIGH": n, "MEDIUM": n, "LOW": n },
          "findings": [ { ...per anomaly... }, ... ]
        }
        """
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        findings = []

        for r in results:
            summary[r.severity] = summary.get(r.severity, 0) + 1
            ev = r.event
            findings.append({
                "rank":           len(findings) + 1,
                "severity":       r.severity,
                "fused_score":    round(r.fused_score, 2),
                "timestamp":      get_field(ev, "@timestamp") or None,
                "event_module":   get_field(ev, "event.module") or None,
                "event_action":   get_field(ev, "event.action") or None,
                "event_outcome":  get_field(ev, "event.outcome") or None,
                "source_ip":      get_field(ev, "source.ip") or None,
                "destination_ip": get_field(ev, "destination.ip") or None,
                "destination_port": get_field(ev, "destination.port") or None,
                "user":           get_field(ev, "user.name") or None,
                "message":        get_field(ev, "message") or None,
                "triggered_rules": r.triggered_rules,
                "top_features":   r.top_features,
                "organization":   get_field(ev, "organization.name") or None,
                "observer_name":  get_field(ev, "observer.name") or None,
                "network_protocol": get_field(ev, "network.protocol") or None,
                "original_event": ev,   # full ECS event preserved
            })

        report = {
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "summary":        summary,
            "findings":       findings,
        }

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False, default=str)

        print(f"[SeverityEngine] Report saved → {output_path}")

    # ------------------------------------------------------------------ #
    # Rich report
    # ------------------------------------------------------------------ #

    def print_report(self, results: List[AnomalyResult]):
        try:
            from rich.console import Console
            from rich.table   import Table
            from rich.panel   import Panel
            from rich         import box
            _rich = True
        except ImportError:
            _rich = False

        if not results:
            msg = "No anomalies detected above threshold."
            if _rich:
                from rich.console import Console
                Console().print(f"[green]{msg}[/green]")
            else:
                print(msg)
            return

        # Group by severity
        groups: Dict[str, List[AnomalyResult]] = {
            "CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [],
        }
        for r in results:
            groups.get(r.severity, groups["LOW"]).append(r)

        severity_colors = {
            "CRITICAL": "bold red",
            "HIGH":     "bold yellow",
            "MEDIUM":   "yellow",
            "LOW":      "cyan",
        }

        if _rich:
            from rich.console import Console
            from rich.panel   import Panel
            from rich         import box
            console = Console()
            console.print()
            console.print(Panel(
                f"[bold white]Anomaly Detection Report — "
                f"{sum(len(v) for v in groups.values())} finding(s)[/bold white]",
                style="bold blue",
            ))
        else:
            print("\n" + "="*60)
            print(f"Anomaly Detection Report — "
                  f"{sum(len(v) for v in groups.values())} finding(s)")
            print("="*60)

        counter = 1
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            bucket = groups[sev]
            if not bucket:
                continue

            if _rich:
                console.print(
                    f"\n[{severity_colors[sev]}]{sev} ANOMALIES "
                    f"({len(bucket)} finding(s)):[/{severity_colors[sev]}]"
                )
            else:
                print(f"\n{sev} ANOMALIES ({len(bucket)} finding(s)):")

            for r in bucket:
                ev = r.event
                ts        = get_field(ev, "@timestamp") or "unknown"
                src_ip    = get_field(ev, "source.ip")  or "—"
                dst_ip    = get_field(ev, "destination.ip") or "—"
                dst_port  = get_field(ev, "destination.port") or "—"
                module    = get_field(ev, "event.module") or "—"
                action    = get_field(ev, "event.action") or "—"
                outcome   = get_field(ev, "event.outcome") or "—"
                user      = get_field(ev, "user.name") or "—"
                message   = (get_field(ev, "message") or "")[:120]
                rules_str = ", ".join(r.triggered_rules) if r.triggered_rules else "none"
                feats_str = ", ".join(r.top_features) if r.top_features else "—"

                if _rich:
                    console.print(
                        f"\n  [{severity_colors[sev]}]{counter}. Score: "
                        f"{r.fused_score:.1f}[/{severity_colors[sev]}]"
                    )
                    console.print(f"     [dim]Timestamp   :[/dim] {ts}")
                    console.print(f"     [dim]Module      :[/dim] {module}")
                    console.print(f"     [dim]Source IP   :[/dim] {src_ip}")
                    console.print(f"     [dim]Destination :[/dim] {dst_ip}:{dst_port}")
                    console.print(f"     [dim]User        :[/dim] {user}")
                    console.print(f"     [dim]Action      :[/dim] {action}  "
                                  f"Outcome: {outcome}")
                    console.print(f"     [dim]Rules       :[/dim] [bold]{rules_str}[/bold]")
                    console.print(f"     [dim]Top features:[/dim] {feats_str}")
                    console.print(f"     [dim]Message     :[/dim] {message}")
                else:
                    print(f"\n  {counter}. Score: {r.fused_score:.1f}")
                    print(f"     Timestamp   : {ts}")
                    print(f"     Module      : {module}")
                    print(f"     Source IP   : {src_ip}")
                    print(f"     Destination : {dst_ip}:{dst_port}")
                    print(f"     User        : {user}")
                    print(f"     Action/Out  : {action} / {outcome}")
                    print(f"     Rules       : {rules_str}")
                    print(f"     Top features: {feats_str}")
                    print(f"     Message     : {message}")

                counter += 1

        if _rich:
            console.print()
