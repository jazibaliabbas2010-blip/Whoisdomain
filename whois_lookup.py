import asyncio
import json
import logging
import aiohttp
import dns.resolver
import whois
from config import LOOKUP_TIMEOUT_SECONDS

log = logging.getLogger(__name__)
DNS_TYPES = ("NS", "A", "MX", "TXT")

def _clean(value):
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if v]
    return str(value)

def _whois_sync(domain):
    data = whois.whois(domain)
    if not data:
        return None
    result = {}
    for key in ("domain_name", "registrar", "creation_date", "expiration_date",
                "updated_date", "name_servers", "emails", "status", "org", "country"):
        try:
            value = getattr(data, key, None)
        except Exception:
            value = None
        result[key] = _clean(value)
    if not any(result.get(k) for k in ("domain_name", "registrar", "creation_date",
                                        "expiration_date", "name_servers", "status")):
        return None
    result["source"] = "WHOIS"
    return result

async def _rdap(domain):
    url = f"https://rdap.org/domain/{domain}"
    timeout = aiohttp.ClientTimeout(total=LOOKUP_TIMEOUT_SECONDS)
    headers = {"Accept": "application/rdap+json, application/json"}
    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        async with session.get(url, allow_redirects=True) as response:
            if response.status != 200:
                return None
            payload = await response.json(content_type=None)
    if not isinstance(payload, dict) or not payload.get("ldhName"):
        return None
    result = {
        "domain_name": payload.get("ldhName") or payload.get("unicodeName"),
        "registrar": None, "creation_date": None, "expiration_date": None,
        "updated_date": None, "name_servers": [], "emails": [], "status": payload.get("status", []),
        "org": None, "country": None, "source": "RDAP",
    }
    for event in payload.get("events", []):
        action = (event.get("eventAction") or "").lower()
        date = event.get("eventDate")
        if action in ("registration", "registered"):
            result["creation_date"] = date
        elif action in ("expiration", "expired"):
            result["expiration_date"] = date
        elif action in ("last changed", "last update of rdap database"):
            result["updated_date"] = date
    for entity in payload.get("entities", []):
        roles = [r.lower() for r in entity.get("roles", [])]
        vcard = entity.get("vcardArray", [])
        props = vcard[1] if len(vcard) > 1 and isinstance(vcard[1], list) else []
        for prop in props:
            if len(prop) >= 4:
                name, value = prop[0], prop[3]
                if name == "fn" and "registrar" in roles and not result["registrar"]:
                    result["registrar"] = str(value)
                if name == "email":
                    result["emails"].append(str(value))
    result["name_servers"] = [n.get("ldhName") for n in payload.get("nameservers", []) if n.get("ldhName")]
    return result

async def get_whois_data(domain):
    try:
        result = await asyncio.wait_for(asyncio.to_thread(_whois_sync, domain), timeout=LOOKUP_TIMEOUT_SECONDS)
        if result:
            return result
    except Exception as exc:
        log.info("WHOIS library failed for %s: %s", domain, exc)
    try:
        return await _rdap(domain)
    except Exception as exc:
        log.info("RDAP failed for %s: %s", domain, exc)
        return None

def _dns_sync(domain):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = LOOKUP_TIMEOUT_SECONDS
    result = {}
    for kind in DNS_TYPES:
        try:
            answers = resolver.resolve(domain, kind, lifetime=LOOKUP_TIMEOUT_SECONDS)
            if kind == "MX":
                result[kind] = [f"{a.preference} {a.exchange.to_text()}" for a in answers]
            elif kind == "TXT":
                result[kind] = [b"".join(a.strings).decode("utf-8", "replace") for a in answers]
            else:
                result[kind] = [a.to_text().rstrip(".") for a in answers]
        except Exception:
            result[kind] = []
    return result

async def _dns_google(domain):
    timeout = aiohttp.ClientTimeout(total=LOOKUP_TIMEOUT_SECONDS)
    result = {}
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for kind in DNS_TYPES:
            try:
                async with session.get("https://dns.google/resolve",
                    params={"name": domain, "type": kind}, headers={"Accept": "application/dns-json"}) as resp:
                    if resp.status != 200:
                        result[kind] = []
                        continue
                    data = await resp.json(content_type=None)
                    result[kind] = [a.get("data", "") for a in data.get("Answer", []) if a.get("data")]
            except Exception:
                result[kind] = []
    return result

async def get_dns_data(domain):
    try:
        data = await asyncio.wait_for(asyncio.to_thread(_dns_sync, domain),
                                      timeout=LOOKUP_TIMEOUT_SECONDS + 1)
        if any(data.get(k) for k in DNS_TYPES):
            return data
    except Exception as exc:
        log.info("dnspython failed for %s: %s", domain, exc)
    try:
        return await _dns_google(domain)
    except Exception as exc:
        log.info("Google DNS fallback failed for %s: %s", domain, exc)
        return {k: [] for k in DNS_TYPES}
