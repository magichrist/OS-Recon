import asyncio
import os
from dataclasses import dataclass, field
from typing import Optional

from pydantic import BaseModel


class EnrichmentFinding(BaseModel):
    provider: str
    target_type: str
    target_value: str
    summary: str
    severity: str
    details: dict = {}
    source_url: Optional[str] = None


@dataclass
class EnrichmentConfig:
    hibp_api_key: Optional[str] = None
    dehashed_email: Optional[str] = None
    dehashed_key: Optional[str] = None
    hunter_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None

    @classmethod
    def from_env(cls):
        return cls(
            hibp_api_key=os.getenv("HIBP_API_KEY"),
            dehashed_email=os.getenv("DEHASHED_EMAIL"),
            dehashed_key=os.getenv("DEHASHED_KEY"),
            hunter_api_key=os.getenv("HUNTER_API_KEY"),
            shodan_api_key=os.getenv("SHODAN_API_KEY"),
            virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY"),
        )

    @property
    def has_any(self) -> bool:
        return bool(
            self.hibp_api_key
            or (self.dehashed_email and self.dehashed_key)
            or self.hunter_api_key
            or self.shodan_api_key
            or self.virustotal_api_key
        )


EnrichmentProvider = tuple[str, list[str]]

REGISTRY: dict[str, tuple] = {}


def register(provider_name: str, target_types: list[str]):
    def decorator(func):
        REGISTRY[provider_name] = (func, target_types)
        return func
    return decorator


def collect_targets(
    social_data: dict | None,
    git_data: dict | None,
    pry_data: list | None,
) -> dict[str, set[str]]:
    targets: dict[str, set[str]] = {
        "emails": set(),
        "usernames": set(),
        "domains": set(),
        "ips": set(),
    }

    if git_data:
        exposed = git_data.get("exposed_emails", [])
        if isinstance(exposed, list):
            targets["emails"].update(e.lower() for e in exposed if e)

    if social_data:
        username = social_data.get("username", "")
        if username:
            targets["usernames"].add(username.lower())

        gh_users = social_data.get("github_username", [])
        if isinstance(gh_users, str):
            gh_users = [gh_users]
        if isinstance(gh_users, list):
            targets["usernames"].update(u.lower() for u in gh_users if u)

        for r in social_data.get("results", []):
            url = r.get("url", "")
            if "://" in url:
                domain = url.split("/")[2].lower()
                targets["domains"].add(domain.lstrip("www."))

    if pry_data:
        for item in pry_data:
            if isinstance(item, dict):
                url = item.get("url", "")
                if "://" in url:
                    domain = url.split("/")[2].lower()
                    targets["domains"].add(domain.lstrip("www."))

    return targets


async def run_enrichment_pipeline(
    social_data: dict | None = None,
    git_data: dict | None = None,
    pry_data: list | None = None,
) -> list[EnrichmentFinding]:
    config = EnrichmentConfig.from_env()

    if not config.has_any:
        return []

    targets = collect_targets(social_data, git_data, pry_data)
    targets_flat = {k: list(v) for k, v in targets.items()}

    tasks = []

    for name, (func, target_types) in REGISTRY.items():
        relevant = {t: targets_flat[t] for t in target_types if targets_flat.get(t)}
        if relevant:
            tasks.append(func(relevant, config))

    if not tasks:
        return []

    results = await asyncio.gather(*tasks, return_exceptions=True)

    findings = []
    for r in results:
        if isinstance(r, Exception):
            continue
        if isinstance(r, list):
            findings.extend(r)

    return findings
