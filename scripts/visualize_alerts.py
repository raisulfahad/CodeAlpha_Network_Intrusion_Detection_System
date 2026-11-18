#!/usr/bin/env python3
"""visualize_alerts.py - bar chart of Suricata alert frequency by signature.

Usage: python3 visualize_alerts.py [eve.json] [-o alerts_summary.png]
"""
import argparse
import sys

import matplotlib
matplotlib.use("Agg")  # headless-safe
import matplotlib.pyplot as plt
import pandas as pd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log", nargs="?", default="/var/log/suricata/eve.json")
    ap.add_argument("-o", "--output", default="alerts_summary.png")
    args = ap.parse_args()

    df = pd.read_json(args.log, lines=True)
    if "event_type" not in df.columns:
        sys.exit("No events found in log.")
    alerts = df[df["event_type"] == "alert"].copy()
    if alerts.empty:
        sys.exit("No alert events found in log.")

    alerts["signature"] = alerts["alert"].apply(lambda a: a.get("signature", "unknown"))
    counts = alerts["signature"].value_counts().sort_values()

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.barh(counts.index, counts.values, color="#2a6fdb")
    ax.bar_label(bars, padding=3)
    ax.set_xlabel("Number of alerts")
    ax.set_title(f"Suricata alerts by signature (total: {len(alerts)})")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(args.output, dpi=150)
    print(f"Saved {args.output}")
    print(counts.sort_values(ascending=False).to_string())


if __name__ == "__main__":
    main()
