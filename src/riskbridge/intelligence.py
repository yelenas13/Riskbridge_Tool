from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import time
from typing import Iterable

import requests

from .utils import clamp, load_json, save_json

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HEADERS = {"User-Agent": "RiskBridge/0.4 (+https://github.com/yelenas13/Riskbridge_Tool)"}


def _chunks(items: list[str], size: int) -> Iterable[list[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _get_json(
    url: str,
    *,
    params: dict | None = None,
    retries: int = 3,
    timeout: int = 20,
) -> dict:
    """GET JSON with conservative retry/backoff.

    RiskBridge never fabricates security values if an upstream source fails.
    Callers decide how to represent unavailable data.
    """
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            response = requests.get(url, params=params, headers=HEADERS, timeout=timeout)
            if response.status_code == 429:
                time.sleep(2 ** (attempt + 1))
                continue
            response.raise_for_status()
            return response.json()
        except Exception as exc:  # network/source failures are surfaced to the caller
            last_error = exc
            if attempt < retries - 1:
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
    return {
        "cvss_version": None,
        "cvss_score": None,
        "cvss_severity": None,
        "cvss_vector": None,
    }


def _english_description(cve: dict) -> str:
    descriptions = cve.get("descriptions") or []
    for item in descriptions:
        if item.get("lang") == "en":
            return str(item.get("value", ""))
    return str(descriptions[0].get("value", "")) if descriptions else ""


def _short_description(text: str, max_chars: int = 520) -> str:
    text = " ".join(str(text or "").split())
    if len(text) <= max_chars:
        return text
    cut = text[: max_chars - 1]
    last_sentence = max(cut.rfind(". "), cut.rfind("; "))
    if last_sentence > max_chars * 0.55:
        cut = cut[: last_sentence + 1]
    return cut.rstrip() + "…"


def _cwes(cve: dict) -> str:
    found: set[str] = set()
    for weakness in cve.get("weaknesses") or []:
        for item in weakness.get("description") or []:
            value = str(item.get("value", ""))
            if value.startswith("CWE-"):
                found.add(value)
    return ", ".join(sorted(found))


def _parse_cpe(criteria: str) -> tuple[str, str, str, str]:
    # cpe:2.3:<part>:<vendor>:<product>:<version>:...
    parts = str(criteria or "").split(":")
    part = parts[2] if len(parts) > 2 else ""
    vendor = parts[3] if len(parts) > 3 else ""
    product = parts[4] if len(parts) > 4 else ""
    version = parts[5] if len(parts) > 5 else ""
    return part, vendor, product, version


def _cpe_matches(cve: dict) -> list[dict]:
    matches: list[dict] = []

    def walk(nodes: list[dict]) -> None:
        for node in nodes or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria") or match.get("cpe23Uri") or ""
                part, vendor, product, version = _parse_cpe(criteria)
                matches.append(
                    {
                        "criteria": criteria,
                        "part": part,
                        "vendor": vendor,
                        "product": product,
                        "version": version,
                        "version_start_including": match.get("versionStartIncluding"),
                        "version_start_excluding": match.get("versionStartExcluding"),
                        "version_end_including": match.get("versionEndIncluding"),
                        "version_end_excluding": match.get("versionEndExcluding"),
                    }
                )
            walk(node.get("children") or [])

    for cfg in cve.get("configurations") or []:
        # NVD 2.0 configurations are normally a list of objects containing nodes.
        # Some transformed payloads may already expose nodes directly.
        if isinstance(cfg, dict) and "nodes" in cfg:
            walk(cfg.get("nodes") or [])
        elif isinstance(cfg, dict):
            walk([cfg])
    return matches


def _affected_products(matches: list[dict], limit: int = 25) -> str:
    products: list[str] = []
    seen: set[str] = set()
    for match in matches:
        vendor = match.get("vendor") or ""
        product = match.get("product") or ""
        exact_version = match.get("version") or ""
        bounds: list[str] = []
        if exact_version not in {"", "*", "-"}:
            bounds.append(f"={exact_version}")
        if match.get("version_start_including"):
            bounds.append(f">={match['version_start_including']}")
        if match.get("version_start_excluding"):
            bounds.append(f">{match['version_start_excluding']}")
        if match.get("version_end_including"):
            bounds.append(f"<={match['version_end_including']}")
        if match.get("version_end_excluding"):
            bounds.append(f"<{match['version_end_excluding']}")
        label = f"{vendor}:{product}"
        if bounds:
            label += f" ({' '.join(bounds)})"
        if label not in seen:
            seen.add(label)
            products.append(label)
        if len(products) >= limit:
            break
    return "; ".join(products)


def _reference_sets(cve: dict, limit: int = 8) -> dict[str, str]:
    refs = cve.get("references") or []
    vendor: list[str] = []
    patch: list[str] = []
    mitigation: list[str] = []
    all_refs: list[str] = []

    for ref in refs:
        url = str(ref.get("url") or "").strip()
        if not url:
            continue
        if url not in all_refs:
            all_refs.append(url)
        tags = {str(t).lower() for t in ref.get("tags") or []}
        if "vendor advisory" in tags and url not in vendor:
            vendor.append(url)
        if tags.intersection({"patch", "release notes"}) and url not in patch:
            patch.append(url)
        if tags.intersection({"mitigation", "workaround"}) and url not in mitigation:
            mitigation.append(url)

    preferred = vendor or patch or mitigation or all_refs
    return {
        "advisory_urls": " | ".join(preferred[:limit]),
        "vendor_advisory_urls": " | ".join(vendor[:limit]),
        "patch_reference_urls": " | ".join(patch[:limit]),
        "mitigation_reference_urls": " | ".join(mitigation[:limit]),
        "reference_urls": " | ".join(all_refs[:limit]),
    }


def _exposure_hint(cvss_vector: str | None, cwe_text: str, description: str) -> str:
    vector = cvss_vector or ""
    cwes = set(re.findall(r"CWE-\d+", cwe_text or ""))
    text = (description or "").lower()
    network = "AV:N" in vector
    adjacent = "AV:A" in vector
    local = "AV:L" in vector

    if network and cwes.intersection({"CWE-78", "CWE-94", "CWE-502", "CWE-787", "CWE-120"}):
        return "Network-reachable code-execution or memory-corruption surface"
    if cwes.intersection({"CWE-287", "CWE-306", "CWE-798", "CWE-862", "CWE-863"}) or "authentication" in text:
        return "Authentication, authorization, or identity boundary"
    if cwes.intersection({"CWE-89", "CWE-79", "CWE-22", "CWE-918"}) or any(
        word in text for word in ("web server", "web application", "http", "api")
    ):
        return "Web or API application surface"
    if local:
        return "Local host / privilege boundary"
    if adjacent:
        return "Adjacent-network service surface"
    if network:
        return "Network-facing service surface"
    return "Exposure depends on product role and deployment context"


def fetch_nvd(cve_ids: list[str], cache_dir: str | Path | None = None) -> dict[str, dict]:
    ids = list(dict.fromkeys(c.strip().upper() for c in cve_ids if c))
    result: dict[str, dict] = {}
    cache = Path(cache_dir) if cache_dir else None
    if cache:
        cache.mkdir(parents=True, exist_ok=True)

    missing: list[str] = []
    for cve_id in ids:
        cached = load_json(cache / f"nvd_v04_{cve_id}.json") if cache else None
        if cached:
            result[cve_id] = cached
        else:
            missing.append(cve_id)

    # NVD documents cveIds as a comma-separated parameter, max 100 CVE IDs.
    for chunk in _chunks(missing, 100):
        payload = _get_json(NVD_API, params={"cveIds": ",".join(chunk)})
        for item in payload.get("vulnerabilities") or []:
            cve = item.get("cve", {})
            cid = str(cve.get("id") or "").upper()
            if not cid or cid not in chunk:
                continue
            cvss = _pick_cvss(cve.get("metrics") or {})
            description = _english_description(cve)
            cwe_text = _cwes(cve)
            matches = _cpe_matches(cve)
            references = _reference_sets(cve)
            row = {
                "cve_id": cid,
                **cvss,
                "description": description,
                "description_short": _short_description(description),
                "cwe": cwe_text,
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "vuln_status": cve.get("vulnStatus"),
                "source_identifier": cve.get("sourceIdentifier"),
                "affected_products_nvd": _affected_products(matches),
                "primary_affected_product": (
                    f"{matches[0].get('vendor','')}:{matches[0].get('product','')}" if matches else ""
                ),
                "cpe_matches_json": json.dumps(matches, separators=(",", ":")),
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                **references,
            }
            row["exposure_hint"] = _exposure_hint(
                row.get("cvss_vector"), row.get("cwe", ""), row.get("description", "")
            )
            result[cid] = row
            if cache:
                save_json(cache / f"nvd_v04_{cid}.json", row)

    # Preserve requested IDs even if NVD has not received them yet.
    for cid in ids:
        result.setdefault(
            cid,
            {
                "cve_id": cid,
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                "nvd_record_found": False,
            },
        )
        result[cid].setdefault("nvd_record_found", bool(result[cid].get("description") or result[cid].get("cvss_score")))
    return result


def fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    result: dict[str, dict] = {}
    # FIRST documents a 2000-character limit for the cve query parameter.
    for chunk in _chunks(list(dict.fromkeys(c.upper() for c in cve_ids if c)), 40):
        payload = _get_json(EPSS_API, params={"cve": ",".join(chunk)})
        for row in payload.get("data") or []:
            cid = str(row.get("cve") or "").upper()
            if not cid:
                continue
            result[cid] = {
                "epss": float(row["epss"]),
                "epss_percentile": float(row["percentile"]),
                "epss_date": row.get("date") or row.get("created"),
                "epss_source": "FIRST EPSS",
            }
    return result


def _epss_velocity_from_points(points: list[dict]) -> dict:
    clean: list[dict] = []
    for point in points:
        try:
            clean.append(
                {
                    "date": str(point.get("date") or point.get("created") or ""),
                    "epss": float(point.get("epss")),
                    "percentile": float(point.get("percentile")),
                }
            )
        except (TypeError, ValueError):
            continue
    clean = sorted((p for p in clean if p["date"]), key=lambda p: p["date"])
    if not clean:
        return {
            "epss_delta_7d": None,
            "epss_delta_30d": None,
            "epss_velocity_score": None,
            "epss_trend": "UNAVAILABLE",
            "epss_history_json": "[]",
        }

    latest = clean[-1]["epss"]

    def point_n_days_back(days: int) -> float | None:
        # API time-series is daily and limited to roughly 30 days. Using index distance
        # is robust to occasional missing publication days.
        if len(clean) <= days:
            return clean[0]["epss"] if clean else None
        return clean[-(days + 1)]["epss"]

    p7 = point_n_days_back(7)
    p30 = point_n_days_back(29)
    delta7 = latest - p7 if p7 is not None else None
    delta30 = latest - p30 if p30 is not None else None

    if delta7 is None:
        trend = "UNAVAILABLE"
        velocity_score = None
    elif delta7 >= 0.20:
        trend, velocity_score = "RAPID_RISE", 100.0
    elif delta7 >= 0.10:
        trend, velocity_score = "STRONG_RISE", 85.0
    elif delta7 >= 0.03:
        trend, velocity_score = "RISING", 70.0
    elif delta7 >= 0.01:
        trend, velocity_score = "SLIGHT_RISE", 60.0
    elif delta7 <= -0.10:
        trend, velocity_score = "FALLING_FAST", 20.0
    elif delta7 <= -0.03:
        trend, velocity_score = "FALLING", 30.0
    elif delta7 <= -0.01:
        trend, velocity_score = "SLIGHT_FALL", 40.0
    else:
        trend, velocity_score = "STABLE", 50.0

    return {
        "epss_delta_7d": round(delta7, 6) if delta7 is not None else None,
        "epss_delta_30d": round(delta30, 6) if delta30 is not None else None,
        "epss_velocity_score": velocity_score,
        "epss_trend": trend,
        "epss_history_json": json.dumps(clean, separators=(",", ":")),
    }


def fetch_epss_history(cve_id: str) -> dict:
    """Return FIRST's current EPSS + available 30-day history and a transparent trend label."""
    payload = _get_json(EPSS_API, params={"cve": cve_id.upper(), "scope": "time-series"})
    rows = payload.get("data") or []
    if not rows:
        return _epss_velocity_from_points([])
    current = rows[0]
    points = list(current.get("time-series") or [])
    # FIRST returns the current row separately from the historical array.
    points.append(
        {
            "date": current.get("date") or current.get("created"),
            "epss": current.get("epss"),
            "percentile": current.get("percentile"),
        }
    )
    return _epss_velocity_from_points(points)


def fetch_kev() -> dict[str, dict]:
    payload = _get_json(KEV_URL)
    result: dict[str, dict] = {}
    for row in payload.get("vulnerabilities") or []:
        cid = str(row.get("cveID") or "").upper()
        if cid:
            result[cid] = {
                "known_exploited": True,
                "kev_date_added": row.get("dateAdded"),
                "kev_due_date": row.get("dueDate"),
                "kev_required_action": row.get("requiredAction"),
                "kev_ransomware": row.get("knownRansomwareCampaignUse"),
                "kev_vendor_project": row.get("vendorProject"),
                "kev_product": row.get("product"),
                "kev_vulnerability_name": row.get("vulnerabilityName"),
                "kev_notes": row.get("notes"),
                "kev_source": "CISA Known Exploited Vulnerabilities",
            }
    return result


def enrich_cves(
    cve_ids: list[str],
    cache_dir: str | Path | None = ".riskbridge_cache",
    *,
    include_epss_history: bool = False,
    max_history_cves: int = 12,
) -> dict[str, dict]:
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
                combined[cid]["kev_source"] = "CISA Known Exploited Vulnerabilities (checked; CVE absent)"
    except Exception as exc:
        errors.append(f"KEV: {exc}")

    if include_epss_history:
        for cid in unique[:max_history_cves]:
            try:
                combined[cid].update(fetch_epss_history(cid))
            except Exception as exc:
                # History is enrichment, not a reason to lose the current EPSS score.
                combined[cid].setdefault("epss_trend", "UNAVAILABLE")
                combined[cid]["epss_history_error"] = str(exc)

    now = datetime.now(timezone.utc).isoformat()
    for cid in unique:
        row = combined[cid]
        row["intelligence_checked_at"] = now
        row["intelligence_errors"] = " | ".join(errors)
        row["provenance"] = json.dumps(
            {
                "NVD": row.get("nvd_url"),
                "FIRST_EPSS": "https://api.first.org/data/v1/epss",
                "CISA_KEV": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "Vendor_Advisory": row.get("vendor_advisory_urls") or row.get("advisory_urls"),
                "checked_at": now,
            },
            separators=(",", ":"),
        )
    return combined
