"""Extract indicators of compromise (IOCs) from alerts.

Highlights:
  * decodes PowerShell -EncodedCommand payloads (Base64 of UTF-16LE) and scans them too
  * separates internal (RFC1918) addresses from external ones, so only external
    indicators are sent to threat-intel APIs
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s'\"<>()]+", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
# -e, -en, -enc, -enco..., -encodedcommand followed by a Base64 blob
ENCODED_CMD_RE = re.compile(r"\s-e(?:n(?:c(?:o\w*)?)?)?\s+([A-Za-z0-9+/=]{16,})", re.IGNORECASE)

INTERNAL_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")
]

# Strings that indicate a PowerShell download cradle or in-memory execution
SUSPICIOUS_PS_KEYWORDS = (
    "downloadstring", "downloadfile", "invoke-expression", "iex ", "iex(",
    "net.webclient", "frombase64string", "invoke-webrequest", "start-bitstransfer",
)


@dataclass(frozen=True)
class IOC:
    type: str          # ip | domain | url | sha256 | md5
    value: str
    internal: bool = False


def is_internal_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in net for net in INTERNAL_NETWORKS)


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def decode_powershell(command_line: str | None) -> str | None:
    """Return the decoded script of a PowerShell -EncodedCommand, or None."""
    if not command_line:
        return None
    match = ENCODED_CMD_RE.search(command_line)
    if not match:
        return None
    blob = match.group(1)
    blob += "=" * (-len(blob) % 4)  # fix missing padding
    try:
        return base64.b64decode(blob).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError):
        return None


def suspicious_ps_keywords(decoded: str | None) -> list[str]:
    if not decoded:
        return []
    lowered = decoded.lower()
    return [kw.strip(" (") for kw in SUSPICIOUS_PS_KEYWORDS if kw in lowered]


def extract_iocs(alert: dict) -> list[IOC]:
    """Collect unique IOCs from an alert's fields, command line and decoded PowerShell."""
    found: dict[tuple[str, str], IOC] = {}

    def add(ioc_type: str, value: str) -> None:
        value = value.strip().rstrip(".,;'\"")
        if not value:
            return
        if ioc_type in ("domain", "sha256", "md5"):
            value = value.lower()
        internal = ioc_type == "ip" and is_internal_ip(value)
        found.setdefault((ioc_type, value), IOC(ioc_type, value, internal))

    for field in ("src_ip", "dst_ip"):
        if alert.get(field) and _valid_ipv4(alert[field]):
            add("ip", alert[field])
    if alert.get("sha256"):
        add("sha256", alert["sha256"])

    decoded = decode_powershell(alert.get("command_line"))
    text = " ".join(filter(None, [alert.get("command_line"), decoded]))
    # Remove the Base64 blob itself so it is not mistaken for a hash
    text = ENCODED_CMD_RE.sub(" ", text)

    for url in URL_RE.findall(text):
        add("url", url)
        host = urlparse(url).hostname or ""
        if _valid_ipv4(host):
            add("ip", host)
        elif host:
            add("domain", host)
    for ip in IPV4_RE.findall(text):
        if _valid_ipv4(ip):
            add("ip", ip)
    for h in SHA256_RE.findall(text):
        add("sha256", h)
    for h in MD5_RE.findall(SHA256_RE.sub(" ", text)):
        add("md5", h)

    return list(found.values())
