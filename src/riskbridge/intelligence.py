from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import time
from typing import Iterable

import requests

from .utils import load_json, save_json

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HEADERS = {"User-Agent": "RiskBridge/0.3 (+https://github.com/)"}


def _chunks(items: list[str], size: int) -> Iterable[list[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _get_json(url: str, *, params: dict | None = None, retries: int = 3, timeout: int = 12) -> dict:
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            response = requests.get(url, params=params, headers=HEADERS, timeout=timeout)
            if response.status_code == 429:
                time.sleep(2 ** (attempt + 1))
                continue
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            last_error = exc
            time.sleep(min(2 ** attempt, 8))
    raise RuntimeError(f"Request failed for {url}: {last_error}")


def _pick_cvss(metrics: dict) -> dict:
    for key in ("cvssMetricV40", "cvssMetricV4"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            return {
                "cvss_version": "4.0",
                "cvss_score": data.get("baseScore"),
                "cvss_severity": data.get("baseSeverity"),
                "cvss_vector": data.get("vectorString"),
            }
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            return {
                "cvss_version": "3.1" if key.endswith("31") else "3.0",
                "cvss_score": data.get("baseScore"),
                "cvss_severity": data.get("baseSeverity"),
                "cvss_vector": data.get("vectorString"),
            }
    return {"cvss_version": None, "cvss_score": None, "cvss_severity": None, "cvss_vector": None}


def _english_description(cve: dict) -> str:
    descriptions = cve.get("descriptions") or []
    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def _cwes(cve: dict) -> str:
    found: set[str] = set()
    for weakness in cve.get("weaknesses") or []:
        for item in weakness.get("description") or []:
            value = str(item.get("value", ""))
            if value.startswith("CWE-"):
                found.add(value)
    return ", ".join(sorted(found))


def _affected_products(cve: dict, limit: int = 20) -> str:
    products: set[str] = set()

    def walk(nodes: list[dict]) -> None:
        for node in nodes:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                cpe = match.get("criteria") or match.get("cpe23Uri") or ""
                parts = cpe.split(":")
                vendor = parts[3] if len(parts) > 3 else ""
                product = parts[4] if len(parts) > 4 else ""
                if vendor or product:
                    bounds: list[str] = []
                    if match.get("versionStartIncluding"):
                        bounds.append(f">={match['versionStartIncluding']}")
                    if match.get("versionStartExcluding"):
                        bounds.append(f">{match['versionStartExcluding']}")
                    if match.get("versionEndIncluding"):
                        bounds.append(f"<={match['versionEndIncluding']}")
                    if match.get("versionEndExcluding"):
                        bounds.append(f"<{match['versionEndExcluding']}")
                    suffix = f" ({' '.join(bounds)})" if bounds else ""
                    products.add(f"{vendor}:{product}{suffix}")
            walk(node.get("children") or [])

    for cfg in cve.get("configurations") or []:
        walk(cfg.get("nodes") or [])
    return "; ".join(sorted(products)[:limit])


def _advisories(cve: dict, limit: int = 3) -> str:
    refs = cve.get("references") or []
    preferred: list[str] = []
    fallback: list[str] = []
    for ref in refs:
        url = ref.get("url")
        if not url:
            continue
        fallback.append(url)
        tags = {str(t).lower() for t in ref.get("tags") or []}
        if tags.intersection({"vendor advisory", "patch", "release notes", "mitigation", "workaround"}):
            preferred.append(url)
    return " | ".join((preferred or fallback)[:limit])


def _exposure_hint(cvss_vector: str | None, cwe_text: str, description: str) -> str:
    vector = cvss_vector or ""
    cwes = set(re.findall(r"CWE-\d+", cwe_text or ""))
    text = (description or "").lower()
    network = "AV:N" in vector
    local = "AV:L" in vector

    if network and cwes.intersection({"CWE-78", "CWE-94", "CWE-502", "CWE-787", "CWE-120"}):
        return "Network-reachable code-execution or memory-corruption surface"
    if cwes.intersection({"CWE-287", "CWE-306", "CWE-798"}) or "authentication" in text:
        return "Authentication or identity boundary"
    if cwes.intersection({"CWE-89", "CWE-79", "CWE-22", "CWE-918"}) or "web" in text:
        return "Web or API application surface"
    if local:
        return "Local host / privilege boundary"
    if network:
        return "Network-facing service surface"
    return "Exposure depends on product role and deployment context"


def fetch_nvd(cve_ids: list[str], cache_dir: str | Path | None = None) -> dict[str, dict]:
    ids = [c.strip().upper() for c in cve_ids if c]
    result: dict[str, dict] = {}
    cache = Path(cache_dir) if cache_dir else None
    if cache:
        cache.mkdir(parents=True, exist_ok=True)

    missing: list[str] = []
    for cve_id in ids:
        cached = load_json(cache / f"nvd_{cve_id}.json") if cache else None
        if cached:
            result[cve_id] = cached
        else:
            missing.append(cve_id)

    for chunk in _chunks(missing, 100):
        payload = _get_json(NVD_API, params={"cveIds": ",".join(chunk)})
        for item in payload.get("vulnerabilities") or []:
            cve = item.get("cve", {})
            cid = cve.get("id")
            if not cid:
                continue
            cvss = _pick_cvss(cve.get("metrics") or {})
            description = _english_description(cve)
            cwe_text = _cwes(cve)
            row = {
                "cve_id": cid,
                **cvss,
                "description": description,
                "cwe": cwe_text,
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "affected_products_nvd": _affected_products(cve),
                "advisory_urls": _advisories(cve),
            }
            row["exposure_hint"] = _exposure_hint(
                row.get("cvss_vector"), row.get("cwe", ""), row.get("description", "")
            )
            result[cid] = row
            if cache:
                save_json(cache / f"nvd_{cid}.json", row)
    return result


def fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    result: dict[str, dict] = {}
    # FIRST documents a 2000-character limit for the cve query parameter. 40 IDs stays safely below it.
    for chunk in _chunks([c.upper() for c in cve_ids], 40):
        payload = _get_json(EPSS_API, params={"cve": ",".join(chunk)})
        for row in payload.get("data") or []:
            result[row["cve"]] = {
                "epss": float(row["epss"]),
                "epss_percentile": float(row["percentile"]),
                "epss_date": row.get("date") or row.get("created"),
            }
    return result


def fetch_kev() -> dict[str, dict]:
    payload = _get_json(KEV_URL)
    result: dict[str, dict] = {}
    for row in payload.get("vulnerabilities") or []:
        cid = row.get("cveID")
        if cid:
            result[cid] = {
                "known_exploited": True,
                "kev_date_added": row.get("dateAdded"),
                "kev_due_date": row.get("dueDate"),
                "kev_required_action": row.get("requiredAction"),
                "kev_ransomware": row.get("knownRansomwareCampaignUse"),
            }
    return result


def enrich_cves(cve_ids: list[str], cache_dir: str | Path | None = ".riskbridge_cache") -> dict[str, dict]:
    unique = list(dict.fromkeys(c.strip().upper() for c in cve_ids if c))
    combined: dict[str, dict] = {cid: {"cve_id": cid} for cid in unique}
    errors: list[str] = []

    try:
        for cid, row in fetch_nvd(unique, cache_dir).items():
            combined.setdefault(cid, {}).update(row)
    except Exception as exc:
        errors.append(f"NVD: {exc}")

    try:
        for cid, row in fetch_epss(unique).items():
            combined.setdefault(cid, {}).update(row)
    except Exception as exc:
        errors.append(f"EPSS: {exc}")

    try:
        kev = fetch_kev()
        for cid in unique:
            if cid in kev:
                combined[cid].update(kev[cid])
            elif "known_exploited" not in combined[cid]:
                combined[cid]["known_exploited"] = False
    except Exception as exc:
        errors.append(f"KEV: {exc}")

    now = datetime.now(timezone.utc).isoformat()
    for cid in unique:
        combined[cid]["intelligence_checked_at"] = now
        combined[cid]["intelligence_errors"] = " | ".join(errors)
    return combined
