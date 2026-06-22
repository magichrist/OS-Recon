import httpx

from . import EnrichmentFinding, register

NAME = "virustotal"
TARGET_TYPES = ["domains", "ips"]

VT_BASE = "https://www.virustotal.com/api/v3"


def _check_harmfulness(stats: dict) -> tuple[str, str]:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = malicious + suspicious
    if total >= 5:
        return "high", f"{malicious} malicious, {suspicious} suspicious detections"
    if total >= 1:
        return "medium", f"{malicious} malicious, {suspicious} suspicious detections"
    return "low", "No detections"


@register(NAME, TARGET_TYPES)
async def enrich(targets: dict[str, list[str]], config) -> list[EnrichmentFinding]:
    if not config.virustotal_api_key:
        return []

    headers = {
        "x-apikey": config.virustotal_api_key,
        "Accept": "application/json",
    }

    findings: list[EnrichmentFinding] = []

    async with httpx.AsyncClient(headers=headers, timeout=10) as client:
        for target_type in ("domains", "ips"):
            for value in targets.get(target_type, []):
                try:
                    vt_type = "domains" if target_type == "domains" else "ip_addresses"
                    resp = await client.get(f"{VT_BASE}/{vt_type}/{value}")

                    if resp.status_code == 200:
                        data = resp.json().get("data", {}).get("attributes", {})
                        stats = data.get("last_analysis_stats", {})

                        severity, summary = _check_harmfulness(stats)

                        if severity != "low":
                            findings.append(
                                EnrichmentFinding(
                                    provider="virustotal",
                                    target_type=target_type,
                                    target_value=value,
                                    summary=f"{value}: {summary} on VirusTotal",
                                    severity=severity,
                                    details={
                                        "value": value,
                                        "analysis_stats": stats,
                                        "reputation": data.get("reputation", 0),
                                        "categories": data.get("categories", {}),
                                    },
                                    source_url=(
                                        f"https://www.virustotal.com/gui/{vt_type.replace('_', '/')}/{value}"
                                    ),
                                )
                            )
                    elif resp.status_code == 204:
                        break
                    elif resp.status_code == 404:
                        continue

                except httpx.RequestError:
                    continue

    return findings
