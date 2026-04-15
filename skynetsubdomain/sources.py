from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

import requests


SourceFetcher = Callable[[str, int], set[str]]


@dataclass(frozen=True)
class Source:
    name: str
    fetch: SourceFetcher


def _clean_names(raw_names: set[str], domain: str) -> set[str]:
    cleaned = set()
    domain = domain.lower().strip(".")
    wildcard = f".{domain}"
    for name in raw_names:
        candidate = name.strip().lower().strip(".")
        if candidate.startswith("*."):
            candidate = candidate[2:]
        if candidate == domain or candidate.endswith(wildcard):
            cleaned.add(candidate)
    return cleaned


def from_crtsh(domain: str, timeout: int) -> set[str]:
    url = "https://crt.sh/"
    response = requests.get(url, params={"q": f"%.{domain}", "output": "json"}, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    names = set()
    for row in data:
        value = row.get("name_value", "")
        for piece in value.splitlines():
            if piece:
                names.add(piece)
    return _clean_names(names, domain)


def from_threatcrowd(domain: str, timeout: int) -> set[str]:
    url = "https://www.threatcrowd.org/searchApi/v2/domain/report/"
    response = requests.get(url, params={"domain": domain}, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    names = set(data.get("subdomains", []) or [])
    return _clean_names(names, domain)


def from_hackertarget(domain: str, timeout: int) -> set[str]:
    url = "https://api.hackertarget.com/hostsearch/"
    response = requests.get(url, params={"q": domain}, timeout=timeout)
    response.raise_for_status()
    names = set()
    for line in response.text.splitlines():
        if "," in line:
            host = line.split(",", 1)[0]
            names.add(host)
    return _clean_names(names, domain)


def from_wayback(domain: str, timeout: int) -> set[str]:
    url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "matchType": "domain",
        "limit": "5000",
    }
    response = requests.get(url, params=params, timeout=timeout)
    response.raise_for_status()
    data = json.loads(response.text)
    names = set()
    for row in data[1:]:
        original = row[0]
        host = original.split("/")[2] if "://" in original else ""
        if host:
            names.add(host.split(":")[0])
    return _clean_names(names, domain)


DEFAULT_SOURCES: list[Source] = [
    Source("crt.sh", from_crtsh),
    Source("ThreatCrowd", from_threatcrowd),
    Source("HackerTarget", from_hackertarget),
    Source("Wayback", from_wayback),
]
