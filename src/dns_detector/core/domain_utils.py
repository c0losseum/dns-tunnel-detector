from __future__ import annotations

import re
from typing import NamedTuple, Optional

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False


class DomainParts(NamedTuple):
    subdomain: str
    domain: str
    suffix: str
    registered_domain: str


# Comprehensive offline multi-part public suffixes
_COMMON_MULTI_SUFFIXES = {
    # Generic & Country 2nd-level
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk",
    "co.id", "web.id", "my.id", "net.id", "biz.id", "ac.id", "sch.id", "go.id", "mil.id", "or.id",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "co.za", "net.za", "org.za", "gov.za",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.tw", "net.tw", "org.tw", "idv.tw",
    "com.hk", "net.hk", "org.hk", "idv.hk",
    "com.mx", "net.mx", "org.mx", "gob.mx",
    "com.ar", "net.ar", "org.ar", "gob.ar",
    "com.tr", "net.tr", "org.tr", "gov.tr",
    "co.kr", "ne.kr", "or.kr", "re.kr",
    # Cloud & Dynamic DNS platforms commonly abused for tunneling
    "s3.amazonaws.com", "azureedge.net", "appspot.com", "duckdns.org",
    "ngrok.io", "github.io", "herokuapp.com", "firebaseapp.com",
}


def split_domain(query_name: str) -> DomainParts:
    """
    Splits a fully-qualified domain name into:
    (subdomain, domain, suffix, registered_domain).
    
    Uses tldextract if available, otherwise falls back to a high-speed
    offline multi-part suffix resolver.
    """
    clean_name = query_name.strip().rstrip(".").lower()

    if not clean_name:
        return DomainParts(subdomain="", domain="", suffix="", registered_domain="")

    # Check if input is IPv4 address
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", clean_name):
        return DomainParts(subdomain="", domain=clean_name, suffix="", registered_domain=clean_name)

    if _HAS_TLDEXTRACT:
        extracted = tldextract.extract(clean_name)
        reg_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        return DomainParts(
            subdomain=extracted.subdomain,
            domain=extracted.domain,
            suffix=extracted.suffix,
            registered_domain=reg_domain,
        )

    # Fast offline fallback logic
    labels = clean_name.split(".")
    if len(labels) == 1:
        return DomainParts(subdomain="", domain=labels[0], suffix="", registered_domain=labels[0])

    # Check 2-level suffix (e.g., co.id, co.uk)
    suffix = ""
    domain = ""
    subdomain = ""

    if len(labels) >= 3:
        two_label_suffix = f"{labels[-2]}.{labels[-1]}"
        if two_label_suffix in _COMMON_MULTI_SUFFIXES:
            suffix = two_label_suffix
            domain = labels[-3]
            subdomain = ".".join(labels[:-3])
            registered_domain = f"{domain}.{suffix}"
            return DomainParts(
                subdomain=subdomain,
                domain=domain,
                suffix=suffix,
                registered_domain=registered_domain,
            )

    # Standard 1-level suffix (e.g., .com, .net, .org, .io, .local)
    suffix = labels[-1]
    domain = labels[-2]
    subdomain = ".".join(labels[:-2])
    registered_domain = f"{domain}.{suffix}"

    return DomainParts(
        subdomain=subdomain,
        domain=domain,
        suffix=suffix,
        registered_domain=registered_domain,
    )
