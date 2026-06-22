import httpx

from . import EnrichmentFinding, register

NAME = "hunter"
TARGET_TYPES = ["emails"]


@register(NAME, TARGET_TYPES)
async def enrich(targets: dict[str, list[str]], config) -> list[EnrichmentFinding]:
    if not config.hunter_api_key:
        return []

    findings: list[EnrichmentFinding] = []

    async with httpx.AsyncClient(timeout=10) as client:
        for email in targets.get("emails", []):
            try:
                resp = await client.get(
                    "https://api.hunter.io/v2/email-verifier",
                    params={"email": email, "api_key": config.hunter_api_key},
                )

                if resp.status_code == 200:
                    data = resp.json().get("data", {})

                    status = data.get("status", "unknown")
                    score = data.get("score", 0)

                    if status in ("invalid", "disposable", "webmail"):
                        findings.append(
                            EnrichmentFinding(
                                provider="hunter",
                                target_type="email",
                                target_value=email,
                                summary=(
                                    f"Email {email} verified as {status} "
                                    f"(confidence: {score}%)"
                                ),
                                severity="info",
                                details={
                                    "status": status,
                                    "score": score,
                                    "sources": data.get("sources", []),
                                },
                            )
                        )

                elif resp.status_code == 401:
                    break

            except httpx.RequestError:
                continue

    return findings
