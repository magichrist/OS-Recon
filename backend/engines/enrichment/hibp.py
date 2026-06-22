import asyncio

import httpx

from . import EnrichmentFinding, register

NAME = "hibp"
TARGET_TYPES = ["emails"]

HIBP_BASE = "https://haveibeenpwned.com/api/v3"


@register(NAME, TARGET_TYPES)
async def enrich(targets: dict[str, list[str]], config) -> list[EnrichmentFinding]:
    if not config.hibp_api_key:
        return []

    findings: list[EnrichmentFinding] = []

    headers = {
        "hibp-api-key": config.hibp_api_key,
        "User-Agent": "OS-Recon/1.0",
    }

    async with httpx.AsyncClient(headers=headers, timeout=10) as client:
        for email in targets.get("emails", []):
            try:
                resp = await client.get(f"{HIBP_BASE}/breachedaccount/{email}")

                if resp.status_code == 200:
                    breaches = resp.json()
                    for breach in breaches:
                        data_classes = breach.get("DataClasses", [])
                        data_str = str(data_classes).lower()
                        has_passwords = any(
                            kw in data_str for kw in ["password", "pass"]
                        )

                        findings.append(
                            EnrichmentFinding(
                                provider="hibp",
                                target_type="email",
                                target_value=email,
                                summary=(
                                    f"Email found in {breach['Name']} breach "
                                    f"({breach.get('BreachDate', 'unknown')})"
                                ),
                                severity="high" if has_passwords else "medium",
                                details={
                                    "breach_name": breach["Name"],
                                    "domain": breach.get("Domain", ""),
                                    "breach_date": breach.get("BreachDate", ""),
                                    "data_classes": data_classes,
                                },
                                source_url=f"https://haveibeenpwned.com/account/{email}",
                            )
                        )

                elif resp.status_code == 429:
                    await asyncio.sleep(1.6)

            except httpx.RequestError:
                continue

    return findings
