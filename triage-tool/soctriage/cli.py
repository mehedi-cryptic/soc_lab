"""Command-line entry point.

    python triage.py samples/sample_alerts.json --offline
    python triage.py /var/ossec/logs/alerts/alerts.json --out reports/today
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import timedelta
from pathlib import Path

from .enrich import Enricher
from .incidents import group_incidents
from .iocs import extract_iocs
from .loader import load_alerts
from .report import generated_now, write_outputs
from .scoring import load_assets, load_privileged, score_alert

TOOL_DIR = Path(__file__).resolve().parent.parent


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="triage",
        description="Enrich, score and group SIEM alerts into prioritized incidents.",
    )
    p.add_argument("input", help="Alert file: .json, .jsonl or .csv (generic schema or raw Wazuh alerts)")
    p.add_argument("--out", default="reports", help="Output directory (default: reports/)")
    p.add_argument("--context", default=str(TOOL_DIR / "context"),
                   help="Folder with assets.csv, privileged_accounts.txt, watchlist.csv")
    p.add_argument("--offline", action="store_true", help="Use only the local watchlist, no API calls")
    p.add_argument("--gap-hours", type=float, default=2.0,
                   help="Quiet period that splits alerts on one host into separate incidents (default: 2)")
    p.add_argument("--min-priority", choices=["P1", "P2", "P3", "P4"], default="P4",
                   help="Only report incidents at or above this priority")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def run(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")
    context = Path(args.context)

    alerts = load_alerts(args.input)
    if not alerts:
        print("No alerts found.")
        return 0

    assets = load_assets(context / "assets.csv")
    privileged = load_privileged(context / "privileged_accounts.txt")
    enricher = Enricher(watchlist_path=context / "watchlist.csv", offline=args.offline,
                        cache_path=TOOL_DIR / ".cache" / "enrichment_cache.json")
    if not args.offline and not (enricher.vt_key or enricher.abuse_key):
        print("[!] No VT_API_KEY or ABUSEIPDB_API_KEY set - using the local watchlist only.", file=sys.stderr)

    for alert in alerts:
        alert["iocs"] = extract_iocs(alert)
        alert["enrichment"] = {ioc.value: enricher.enrich(ioc) for ioc in alert["iocs"]}
        alert["score"], alert["score_reasons"] = score_alert(alert, alert["enrichment"], assets, privileged)
    enricher.save_cache()

    incidents = group_incidents(alerts, gap=timedelta(hours=args.gap_hours))
    cutoff = int(args.min_priority[1])
    incidents = [i for i in incidents if int(i["priority"][1]) <= cutoff]

    meta = {
        "generated": generated_now(),
        "input": Path(args.input).name,
        "mode": "offline (local watchlist only)" if args.offline else "online (watchlist + configured APIs)",
        "alert_count": len(alerts),
        "assets": assets,
    }
    paths = write_outputs(incidents, meta, args.out)

    print(f"\n{'ID':<9}{'PRI':<5}{'SCORE':<7}{'HOST':<14}{'ALERTS':<8}TACTICS")
    for inc in incidents:
        print(f"{inc['id']:<9}{inc['priority']:<5}{inc['score']:<7}{inc['host']:<14}{len(inc['alerts']):<8}"
              f"{' > '.join(inc['tactics'])}")
    print(f"\nReport: {paths['markdown']}\nJSON:   {paths['json']}\nIOCs:   {paths['csv']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    return run(build_parser().parse_args(argv))
