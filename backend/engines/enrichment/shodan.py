import re

import httpx

from . import EnrichmentFinding, register

NAME = "shodan"
TARGET_TYPES = ["domains", "ips"]


def _resolve_domain(domain: str) -> str | None:
    import socket
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, OSError):
        return None


@register(NAME, TARGET_TYPES)
async def enrich(targets: dict[str, list[str]], config) -> list[EnrichmentFinding]:
    if not config.shodan_api_key:
        return []

    findings: list[EnrichmentFinding] = []

    for domain in targets.get("domains", []):
        ip = _resolve_domain(domain)
        if ip:
            if "ips" not in targets:
                targets["ips"] = []
            if ip not in targets["ips"]:
                targets["ips"].append(ip)

    seen_ips = set()

    async with httpx.AsyncClient(timeout=10) as client:
        for ip in targets.get("ips", []):
            if ip in seen_ips:
                continue
            seen_ips.add(ip)

            try:
                resp = await client.get(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": config.shodan_api_key},
                )

                if resp.status_code == 200:
                    data = resp.json()

                    ports = data.get("ports", [])
                    vulns = data.get("vulns", [])
                    org = data.get("org", "")
                    isp = data.get("isp", "")
                    hostnames = data.get("hostnames", [])

                    if vulns:
                        findings.append(
                            EnrichmentFinding(
                                provider="shodan",
                                target_type="ip",
                                target_value=ip,
                                summary=(
                                    f"IP {ip} has {len(vulns)} known vulnerabilities "
                                    f"({', '.join(vulns[:5])})"
                                ),
                                severity="high",
                                details={
                                    "ip": ip,
                                    "vulns": vulns,
                                    "ports": ports,
                                    "org": org,
                                    "isp": isp,
                                    "hostnames": hostnames,
                                },
                                source_url=f"https://www.shodan.io/host/{ip}",
                            )
                        )

                    if ports:
                        service_names = []
                        if data.get("data"):
                            service_names = list(
                                {
                                    svc.get("transport", "") + "/" + (svc.get("_shodan", {}).get("module", ""))
                                    for svc in data.get("data", [])
                                }
                            )

                        findings.append(
                            EnrichmentFinding(
                                provider="shodan",
                                target_type="ip",
                                target_value=ip,
                                summary=(
                                    f"IP {ip} has {len(ports)} open ports: "
                                    f"{', '.join(str(p) for p in ports[:8])}"
                                ),
                                severity="medium",
                                details={
                                    "ip": ip,
                                    "ports": ports,
                                    "services": service_names[:10],
                                    "org": org,
                                    "isp": isp,
                                    "hostnames": hostnames,
                                    "country": data.get("country_name", ""),
                                    "city": data.get("city", ""),
                                },
                                source_url=f"https://www.shodan.io/host/{ip}",
                            )
                        )

                elif resp.status_code == 403:
                    break

            except httpx.RequestError:
                continue

    return findings
