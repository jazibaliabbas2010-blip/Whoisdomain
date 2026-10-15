
import asyncio
import logging

import aiohttp
import dns.resolver
import whois

from config import LOOKUP_TIMEOUT_SECONDS

log = logging.getLogger(__name__)

DNS_TYPES = ("NS", "A", "MX", "TXT")

RDAP_HEADERS = {
    "Accept": "application/rdap+json, application/json",
    "User-Agent": "DomainLookupBot/1.0",
}


def _clean(value):
    if value is None:
        return None

    if isinstance(value, (list, tuple, set)):
        cleaned = [_clean(v) for v in value if v is not None]
        return [v for v in cleaned if v not in (None, "", [])] or None

    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")

    return str(value)


def _has_registration_data(result):
    return bool(
        result
        and any(
            result.get(key)
            for key in (
                "domain_name",
                "registrar",
                "creation_date",
                "expiration_date",
                "name_servers",
                "status",
            )
        )
    )


def _whois_sync(domain):
    data = whois.whois(domain)

    if not data:
        return None

    result = {}

    for key in (
        "domain_name",
        "registrar",
        "creation_date",
        "expiration_date",
        "updated_date",
        "name_servers",
        "emails",
        "status",
        "org",
        "country",
    ):
        try:
            result[key] = _clean(getattr(data, key, None))
        except Exception:
            result[key] = None

    if not _has_registration_data(result):
        return None

    result["source"] = "WHOIS"
    return result


async def _rdap(domain):
    timeout_seconds = max(3, int(LOOKUP_TIMEOUT_SECONDS))

    # Verisign is the authoritative RDAP service for .com and .net.
    urls = []

    if domain.endswith((".com", ".net")):
        urls.append(
            f"https://rdap.verisign.com/{domain.rsplit('.', 1)[1]}/v1/domain/{domain}"
        )

    # Generic RDAP bootstrap/fallback.
    urls.append(f"https://rdap.org/domain/{domain}")

    timeout = aiohttp.ClientTimeout(total=timeout_seconds)

    async with aiohttp.ClientSession(
        timeout=timeout,
        headers=RDAP_HEADERS,
    ) as session:

        for url in urls:
            try:
                async with session.get(
                    url,
                    allow_redirects=True,
                ) as response:

                    if response.status != 200:
                        log.warning(
                            "RDAP returned HTTP %s for %s using %s",
                            response.status,
                            domain,
                            url,
                        )
                        continue

                    payload = await response.json(content_type=None)

                if not isinstance(payload, dict):
                    continue

                domain_name = (
                    payload.get("ldhName")
                    or payload.get("unicodeName")
                )

                if not domain_name:
                    continue

                result = {
                    "domain_name": domain_name,
                    "registrar": None,
                    "creation_date": None,
                    "expiration_date": None,
                    "updated_date": None,
                    "name_servers": [],
                    "emails": [],
                    "status": _clean(payload.get("status")),
                    "org": None,
                    "country": None,
                    "source": "RDAP",
                }

                for event in payload.get("events", []):
                    action = (
                        event.get("eventAction") or ""
                    ).strip().lower()

                    event_date = event.get("eventDate")

                    if action in ("registration", "registered"):
                        result["creation_date"] = event_date

                    elif action in ("expiration", "expired"):
                        result["expiration_date"] = event_date

                    elif action in (
                        "last changed",
                        "last update of rdap database",
                    ):
                        result["updated_date"] = event_date

                for entity in payload.get("entities", []):
                    roles = [
                        str(role).lower()
                        for role in entity.get("roles", [])
                    ]

                    vcard = entity.get("vcardArray", [])
                    props = (
                        vcard[1]
                        if isinstance(vcard, list)
                        and len(vcard) > 1
                        and isinstance(vcard[1], list)
                        else []
                    )

                    for prop in props:
                        if len(prop) < 4:
                            continue

                        name = prop[0]
                        value = prop[3]

                        if name == "email" and value:
                            result["emails"].append(str(value))

                        if (
                            name == "fn"
                            and "registrar" in roles
                            and value
                            and not result["registrar"]
                        ):
                            result["registrar"] = str(value)

                    # Some RDAP responses expose a registrar handle.
                    if "registrar" in roles and not result["registrar"]:
                        result["registrar"] = (
                            entity.get("handle")
                            or entity.get("publicIds", [{}])[0].get("identifier")
                            if entity.get("publicIds")
                            else entity.get("handle")
                        )

                result["name_servers"] = [
                    ns.get("ldhName")
                    for ns in payload.get("nameservers", [])
                    if isinstance(ns, dict) and ns.get("ldhName")
                ]

                result["emails"] = list(dict.fromkeys(result["emails"]))

                if _has_registration_data(result):
                    return result

            except asyncio.CancelledError:
                raise

            except Exception as exc:
                log.warning(
                    "RDAP request failed for %s at %s: %s",
                    domain,
                    url,
                    exc,
                )

    return None


async def get_whois_data(domain):
    domain = domain.strip().lower().rstrip(".")

    if not domain:
        return None

    timeout_seconds = max(3, int(LOOKUP_TIMEOUT_SECONDS))

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_whois_sync, domain),
            timeout=timeout_seconds,
        )

        if _has_registration_data(result):
            return result

        log.info("WHOIS returned no usable registration data for %s", domain)

    except asyncio.CancelledError:
        raise

    except Exception as exc:
        log.warning("WHOIS lookup failed for %s: %s", domain, exc)

    # Always try RDAP after WHOIS failure or empty results.
    try:
        result = await _rdap(domain)

        if _has_registration_data(result):
            return result

    except asyncio.CancelledError:
        raise

    except Exception as exc:
        log.exception("RDAP fallback failed for %s: %s", domain, exc)

    return None


def _dns_sync(domain):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = max(3, int(LOOKUP_TIMEOUT_SECONDS))

    result = {}

    for kind in DNS_TYPES:
        try:
            answers = resolver.resolve(
                domain,
                kind,
                lifetime=max(3, int(LOOKUP_TIMEOUT_SECONDS)),
            )

            if kind == "MX":
                result[kind] = [
                    f"{answer.preference} {answer.exchange.to_text()}"
                    for answer in answers
                ]

            elif kind == "TXT":
                values = []

                for answer in answers:
                    try:
                        value = b"".join(answer.strings).decode(
                            "utf-8", "replace"
                        )
                    except AttributeError:
                        value = answer.to_text().strip('"')

                    values.append(value)

                result[kind] = values

            else:
                result[kind] = [
                    answer.to_text().rstrip(".")
                    for answer in answers
                ]

        except Exception as exc:
            log.debug(
                "DNS %s lookup failed for %s: %s",
                kind,
                domain,
                exc,
            )
            result[kind] = []

    return result


async def _dns_google(domain):
    timeout = aiohttp.ClientTimeout(
        total=max(3, int(LOOKUP_TIMEOUT_SECONDS))
    )

    result = {}

    async with aiohttp.ClientSession(timeout=timeout) as session:
        for kind in DNS_TYPES:
            try:
                async with session.get(
                    "https://dns.google/resolve",
                    params={"name": domain, "type": kind},
                    headers={"Accept": "application/dns-json"},
                ) as response:

                    if response.status != 200:
                        result[kind] = []
                        continue

                    data = await response.json(content_type=None)

                    result[kind] = [
                        answer.get("data", "")
                        for answer in data.get("Answer", [])
                        if answer.get("data")
                    ]

            except asyncio.CancelledError:
                raise

            except Exception as exc:
                log.debug(
                    "Google DNS %s lookup failed for %s: %s",
                    kind,
                    domain,
                    exc,
                )
                result[kind] = []

    return result


async def get_dns_data(domain):
    domain = domain.strip().lower().rstrip(".")

    if not domain:
        return {kind: [] for kind in DNS_TYPES}

    try:
        data = await asyncio.wait_for(
            asyncio.to_thread(_dns_sync, domain),
            timeout=max(3, int(LOOKUP_TIMEOUT_SECONDS)) + 1,
        )

        if any(data.get(kind) for kind in DNS_TYPES):
            return data

    except asyncio.CancelledError:
        raise

    except Exception as exc:
        log.warning("DNS resolver failed for %s: %s", domain, exc)

    try:
        return await _dns_google(domain)

    except asyncio.CancelledError:
        raise

    except Exception as exc:
        log.warning("Google DNS fallback failed for %s: %s", domain, exc)
        return {kind: [] for kind in DNS_TYPES}
