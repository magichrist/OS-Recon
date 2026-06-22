import base64

import httpx

from . import EnrichmentFinding, register

NAME = "dehashed"
TARGET_TYPES = ["emails", "usernames", "domains", "ips"]

DEHASHED_BASE = "https://api.dehashed.com/search"

FIELD_MAP = {
    "emails": "email",
    "usernames": "username",
    "domains": "domain",
    "ips": "ip_address",
}

SEVERITY_MAP = {
    "email": "high",
    "username": "high",
    "password": "critical",
    "hashed_password": "high",
    "name": "medium",
    "address": "medium",
    "phone": "high",
    "ip_address": "medium",
    "domain": "medium",
}


@register(NAME, TARGET_TYPES)
async def enrich(targets: dict[str, list[str]], config) -> list[EnrichmentFinding]:
    if not config.dehashed_email or not config.dehashed_key:
        return []

    auth_str = f"{config.dehashed_email}:{config.dehashed_key}"
    b64_auth = base64.b64encode(auth_str.encode()).decode()

    headers = {
        "Authorization": f"Basic {b64_auth}",
        "Accept": "application/json",
    }

    findings: list[EnrichmentFinding] = []

    async with httpx.AsyncClient(headers=headers, timeout=15) as client:
        for target_type, field in FIELD_MAP.items():
            for value in targets.get(target_type, []):
                try:
                    resp = await client.get(
                        DEHASHED_BASE,
                        params={"query": f"{field}:{value}", "size": 30},
                    )

                    if resp.status_code == 200:
                        body = resp.json()
                        entries = body.get("entries", [])
                        balance = body.get("balance", 0)

                        for entry in entries[:5]:
                            max_sev = "medium"
                            for key in entry:
                                sev = SEVERITY_MAP.get(key, "low")
                                if sev == "critical":
                                    max_sev = "critical"
                                elif sev == "high" and max_sev != "critical":
                                    max_sev = "high"

                            findings.append(
                                EnrichmentFinding(
                                    provider="dehashed",
                                    target_type=target_type,
                                    target_value=value,
                                    summary=(
                                        f"Credential leak found for {field}:{value} "
                                        f"({' '.join(k for k in ['email','username','password','name','phone'] if entry.get(k))})"
                                    ),
                                    severity=max_sev,
                                    details={
                                        "field": field,
                                        "matched_value": value,
                                        "entry_preview": {
                                            k: entry.get(k)
                                            for k in ["email", "username", "name", "password", "hashed_password", "phone", "ip_address", "domain", "database_name"]
                                            if entry.get(k)
                                        },
                                        "database_balance": balance,
                                    },
                                    source_url="https://dehashed.com",
                                )
                            )

                    elif resp.status_code == 401:
                        break

                except httpx.RequestError:
                    continue

    return findings
