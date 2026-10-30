"""Threat-intel enrichment for IOCs.

Order of lookups for each IOC:
  1. local watchlist (context/watchlist.csv)  - always, works offline
  2. on-disk cache (24h TTL)                   - avoids burning free API quota
  3. VirusTotal v3 (hashes, IPs, domains)       - needs VT_API_KEY
  4. AbuseIPDB (IPs)                            - needs ABUSEIPDB_API_KEY

Internal (RFC1918) IPs are never sent to external services.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import time
from pathlib import Path

from .iocs import IOC

log = logging.getLogger(__name__)

VERDICT_RANK = {"unknown": 0, "clean": 1, "suspicious": 2, "malicious": 3}
CACHE_TTL_SECONDS = 24 * 3600


def worst(*verdicts: str) -> str:
    """Return the most severe verdict (malicious > suspicious > clean > unknown)."""
    return max(verdicts, key=lambda v: VERDICT_RANK.get(v, 0)) if verdicts else "unknown"


def load_watchlist(path: str | Path | None) -> dict[tuple[str, str], dict]:
    entries: dict[tuple[str, str], dict] = {}
    if not path or not Path(path).exists():
        return entries
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            key = (row["type"].strip().lower(), row["value"].strip().lower())
            entries[key] = {
                "verdict": row.get("verdict", "malicious").strip().lower(),
                "source": row.get("source", "watchlist").strip(),
                "note": row.get("note", "").strip(),
            }
    return entries


class Enricher:
    VT_URL = "https://www.virustotal.com/api/v3"
    ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(
        self,
        watchlist_path: str | Path | None = None,
        offline: bool = False,
        cache_path: str | Path = ".cache/enrichment_cache.json",
        vt_api_key: str | None = None,
        abuseipdb_api_key: str | None = None,
        vt_delay_seconds: float = 15.0,  # free VT tier = 4 requests/minute
    ) -> None:
        self.watchlist = load_watchlist(watchlist_path)
        self.offline = offline
        self.vt_key = vt_api_key if vt_api_key is not None else os.getenv("VT_API_KEY")
        self.abuse_key = abuseipdb_api_key if abuseipdb_api_key is not None else os.getenv("ABUSEIPDB_API_KEY")
        self.vt_delay = vt_delay_seconds
        self._last_vt_call = 0.0
        self.cache_path = Path(cache_path)
        self.cache = self._load_cache()

    # ---------- cache ----------
    def _load_cache(self) -> dict:
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save_cache(self) -> None:
        if self.offline:
            return
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps(self.cache, indent=2), encoding="utf-8")

    # ---------- public ----------
    def enrich(self, ioc: IOC) -> dict:
        """Return {'verdict', 'sources': [...], 'notes': [...]} for one IOC."""
        result = {"verdict": "unknown", "sources": [], "notes": []}

        if ioc.internal:
            result["notes"].append("internal address - not sent to external intel")
            return result

        wl = self.watchlist.get((ioc.type, ioc.value.lower()))
        if wl:
            result["verdict"] = wl["verdict"]
            result["sources"].append(wl["source"])
            if wl["note"]:
                result["notes"].append(wl["note"])

        if self.offline or ioc.type not in ("ip", "domain", "sha256", "md5"):
            return result

        cache_key = f"{ioc.type}:{ioc.value}"
        cached = self.cache.get(cache_key)
        if cached and time.time() - cached.get("ts", 0) < CACHE_TTL_SECONDS:
            api = cached["result"]
        else:
            api = self._query_apis(ioc)
            self.cache[cache_key] = {"ts": time.time(), "result": api}

        result["verdict"] = worst(result["verdict"], api["verdict"])
        result["sources"].extend(api["sources"])
        result["notes"].extend(api["notes"])
        return result

    # ---------- external APIs ----------
    def _query_apis(self, ioc: IOC) -> dict:
        out = {"verdict": "unknown", "sources": [], "notes": []}
        if self.vt_key:
            vt = self._virustotal(ioc)
            if vt:
                out["verdict"] = worst(out["verdict"], vt["verdict"])
                out["sources"].append("virustotal")
                out["notes"].append(vt["note"])
        if self.abuse_key and ioc.type == "ip":
            ab = self._abuseipdb(ioc.value)
            if ab:
                out["verdict"] = worst(out["verdict"], ab["verdict"])
                out["sources"].append("abuseipdb")
                out["notes"].append(ab["note"])
        return out

    def _virustotal(self, ioc: IOC) -> dict | None:
        import requests  # imported lazily so offline mode needs no dependencies

        endpoint = {"ip": "ip_addresses", "domain": "domains", "sha256": "files", "md5": "files"}[ioc.type]
        wait = self.vt_delay - (time.time() - self._last_vt_call)
        if wait > 0:
            time.sleep(wait)
        self._last_vt_call = time.time()
        try:
            resp = requests.get(
                f"{self.VT_URL}/{endpoint}/{ioc.value}",
                headers={"x-apikey": self.vt_key},
                timeout=20,
            )
        except requests.RequestException as exc:
            log.warning("VirusTotal lookup failed for %s: %s", ioc.value, exc)
            return None
        if resp.status_code == 404:
            return {"verdict": "unknown", "note": "VirusTotal: not seen before"}
        if resp.status_code != 200:
            log.warning("VirusTotal returned HTTP %s for %s", resp.status_code, ioc.value)
            return None
        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        total = sum(int(v) for v in stats.values()) or 1
        verdict = "malicious" if malicious >= 5 else "suspicious" if malicious >= 1 else "clean"
        return {"verdict": verdict, "note": f"VirusTotal: {malicious}/{total} engines flagged"}

    def _abuseipdb(self, ip: str) -> dict | None:
        import requests

        try:
            resp = requests.get(
                self.ABUSE_URL,
                headers={"Key": self.abuse_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=20,
            )
        except requests.RequestException as exc:
            log.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
            return None
        if resp.status_code != 200:
            log.warning("AbuseIPDB returned HTTP %s for %s", resp.status_code, ip)
            return None
        data = resp.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"
        country = data.get("countryCode") or "??"
        return {"verdict": verdict, "note": f"AbuseIPDB: confidence {score}%, {data.get('totalReports', 0)} reports, {country}"}
