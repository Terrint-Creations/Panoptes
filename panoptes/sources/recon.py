"""Active infrastructure recon (Amass / Subfinder / dnstwist / sslyze-lite capabilities)."""
from __future__ import annotations

import asyncio
import random
import ssl
import string

import dns.asyncresolver
import dns.exception
import dns.query
import dns.zone

from panoptes.detect import normalize_domain
from panoptes.models import Entity, Finding
from panoptes.sources.base import Context, Source

WORDLIST = """www mail webmail smtp pop pop3 imap mx mx1 mx2 ns ns1 ns2 ns3 dns dns1 dns2 ftp sftp vpn remote ssh
api api2 dev development stage staging test testing qa uat demo beta alpha preview sandbox lab labs internal intranet
extranet portal admin administrator panel cpanel whm plesk login auth sso id identity accounts account oauth secure
app apps mobile m static cdn assets img images media files upload uploads download downloads docs doc wiki help
support status monitor monitoring grafana kibana prometheus jenkins ci cd git gitlab github bitbucket jira confluence
redmine sonar nexus artifactory registry docker k8s kube kubernetes rancher vault consul blog news shop store cart
checkout pay payment payments billing invoice crm erp hr careers jobs forum community chat meet video owa exchange
autodiscover autoconfig lyncdiscover sip office outlook calendar backup backups db database mysql postgres sql redis
mongo elastic search analytics metrics stats data bi report reports dashboard old new legacy v1 v2 web web1 web2
server srv host gateway gw proxy firewall fw router edge lb origin mirror cloud aws azure gcp s3 storage email
newsletter marketing go link links survey events event partners partner clients client customer customers corp
ext external stg prod production preprod dr crm2 mail2 smtp2 relay mta mailgun sendgrid""".split()


def _resolver(ctx: Context) -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    r.lifetime = min(ctx.options.timeout, 6)
    return r


async def resolve_a(resolver, name: str) -> list[str]:
    try:
        return sorted(r.to_text() for r in await resolver.resolve(name, "A"))
    except (dns.exception.DNSException, OSError):
        return []


async def resolve_many(names, ctx: Context, limit: int = 100) -> dict[str, list[str]]:
    resolver = _resolver(ctx)
    sem = asyncio.Semaphore(limit)

    async def one(n):
        async with sem:
            return n, await resolve_a(resolver, n)
    return dict(await asyncio.gather(*(one(n) for n in names)))


class DNSBruteSource(Source):
    name = "dns-bruteforce"
    kinds = ("domain",)
    description = "Active DNS: zone-transfer (AXFR) attempt on every nameserver + wordlist brute force with wildcard filtering"

    async def search(self, entity: Entity, ctx: Context):
        if not ctx.options.active_dns:
            return
        domain = entity.value
        resolver = _resolver(ctx)

        # Zone transfer: a misconfiguration that hands over the entire zone.
        try:
            ns = [r.to_text().rstrip(".") for r in await resolver.resolve(domain, "NS")]
        except (dns.exception.DNSException, OSError):
            ns = []
        for server in ns:
            ips = await resolve_a(resolver, server)
            if not ips:
                continue
            try:
                zone = await asyncio.to_thread(lambda: dns.zone.from_xfr(dns.query.xfr(ips[0], domain, lifetime=8)))
            except Exception:
                continue
            names = sorted({f"{n}.{domain}".lstrip("@.") for n in zone.nodes.keys() if str(n) != "@"})
            yield Finding(category="insight", title="Zone transfer allowed", value=f"{server} leaked {len(names)} records",
                          source=self.name, target=entity, confidence=0.99, data={"severity": "high", "server": server})
            for n in names:
                yield Finding(category="subdomain", title=n, value=n, source=self.name, target=entity,
                              sources={"axfr"}, confidence=0.99)
            break

        # Wildcard detection, then brute force.
        rand = "".join(random.choices(string.ascii_lowercase, k=14))
        wildcard = set(await resolve_a(resolver, f"{rand}.{domain}"))
        if wildcard:
            ctx.log(f"dns-bruteforce: {domain} has wildcard DNS ({', '.join(wildcard)}); filtering those answers")
        names = [f"{w}.{domain}" for w in dict.fromkeys(WORDLIST)]
        ctx.progress(self.name, entity, 0, len(names))
        found = await resolve_many(names, ctx)
        ctx.progress(self.name, entity, len(names), len(names))
        for name, ips in sorted(found.items()):
            if ips and set(ips) != wildcard:
                yield Finding(category="subdomain", title=name, value=name, source=self.name, target=entity,
                              sources={"bruteforce"}, confidence=0.85, data={"ips": ips})


class TLSCertificateSource(Source):
    name = "tls-certificate"
    kinds = ("domain",)
    description = "Live TLS certificate: issuer, validity, and other domains on the same certificate (SANs)"

    async def search(self, entity: Entity, ctx: Context):
        domain = entity.value
        cert, error = None, None
        for ctx_ssl in (ssl.create_default_context(),):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(domain, 443, ssl=ctx_ssl, server_hostname=domain), ctx.options.timeout)
                cert = writer.get_extra_info("ssl_object").getpeercert()
                writer.close()
            except ssl.SSLCertVerificationError as exc:
                error = exc.verify_message or str(exc)
            except (OSError, asyncio.TimeoutError) as exc:
                error = exc.__class__.__name__
        base = dict(source=self.name, target=entity, url=f"https://crt.sh/?q={domain}")
        if not cert:
            if error and "Timeout" not in error and "ConnectionRefused" not in error:
                yield Finding(category="insight", title="TLS certificate problem", value=error, confidence=0.9,
                              data={"severity": "medium"}, **base)
            return
        flat = lambda seq: ", ".join(f"{k}={v}" for rdn in seq for k, v in rdn)
        yield Finding(category="tls", title="Issuer", value=flat(cert.get("issuer", ())), confidence=0.99, **base)
        yield Finding(category="tls", title="Subject", value=flat(cert.get("subject", ())), confidence=0.99, **base)
        yield Finding(category="tls", title="Valid", value=f"{cert.get('notBefore')} → {cert.get('notAfter')}",
                      confidence=0.99, **base)
        sans = sorted({v.lower().lstrip("*.") for k, v in cert.get("subjectAltName", ()) if k == "DNS"})
        for san in sans:
            if san == domain or san.endswith("." + domain):
                yield Finding(category="subdomain", title=san, value=san, source=self.name, target=entity,
                              sources={"tls-san"}, confidence=0.95)
            else:
                yield Finding(category="related-domain", title="Shares TLS certificate", value=san, confidence=0.8,
                              pivots=[Entity("domain", normalize_domain(san))], **base)


# ----------------------------------------------------------------------------- lookalikes (dnstwist)

KEYBOARD = {c: n for c, n in zip("qwertyuiopasdfghjklzxcvbnm", [
    "wa", "qeas", "wrds", "etfd", "rygf", "tuhg", "yijh", "uokj", "iplk", "ol", "qwsz", "weadxz", "erfscx",
    "rtgdvc", "tyhfbv", "yujgnb", "uikhmn", "iolkm", "opl", "asx", "zsdc", "xdfv", "cfgb", "vghn", "bhjm", "njk"])}
HOMOGLYPHS = {"o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "e": ["3"], "a": ["4"], "s": ["5"], "m": ["rn"], "w": ["vv"],
              "g": ["q"], "b": ["d"], "d": ["b", "cl"], "rn": ["m"], "vv": ["w"], "cl": ["d"]}
TLDS = ["com", "net", "org", "co", "io", "info", "biz", "xyz", "app", "online", "site", "shop", "us", "eu", "dev"]


def permutations(domain: str) -> dict[str, str]:
    parts = domain.split(".")
    if len(parts) < 2:
        return {}
    name, tld = ".".join(parts[:-1]), parts[-1]
    if len(parts) > 2 and len(parts[-2]) <= 3:      # example.co.uk
        name, tld = ".".join(parts[:-2]), ".".join(parts[-2:])
    out: dict[str, str] = {}

    def add(n, technique):
        n = n.strip("-.")
        if n and n != name and all(c.isalnum() or c in "-." for c in n):
            out.setdefault(f"{n}.{tld}", technique)

    for i in range(len(name)):
        add(name[:i] + name[i + 1:], "omission")
        add(name[:i] + name[i] + name[i:], "repetition")
        if i < len(name) - 1:
            add(name[:i] + name[i + 1] + name[i] + name[i + 2:], "transposition")
        for k in KEYBOARD.get(name[i], ""):
            add(name[:i] + k + name[i + 1:], "replacement")
            add(name[:i] + k + name[i:], "insertion")
        if 0 < i < len(name):
            add(name[:i] + "-" + name[i:], "hyphenation")
            add(name[:i] + "." + name[i:], "subdomain")
        for vowel in "aeiou":
            if name[i] in "aeiou" and vowel != name[i]:
                add(name[:i] + vowel + name[i + 1:], "vowel-swap")
    for src, alts in HOMOGLYPHS.items():
        start = 0
        while (idx := name.find(src, start)) != -1:
            for alt in alts:
                add(name[:idx] + alt + name[idx + len(src):], "homoglyph")
            start = idx + 1
    for c in string.ascii_lowercase:
        add(name + c, "addition")
    for word in ("login", "secure", "account", "support", "my", "online", "app", "verify"):
        add(f"{name}-{word}", "dictionary")
        add(f"{word}-{name}", "dictionary")
    for t in TLDS:
        if t != tld:
            out.setdefault(f"{name}.{t}", "tld-swap")
    out.pop(domain, None)
    return out


class LookalikeSource(Source):
    name = "lookalikes"
    kinds = ("domain",)
    description = "dnstwist-style typosquat / phishing lookalike domains that are actually registered (with MX check)"

    async def search(self, entity: Entity, ctx: Context):
        if not ctx.options.active_dns:
            return
        perms = permutations(entity.value)
        ctx.progress(self.name, entity, 0, len(perms))
        resolved = await resolve_many(list(perms), ctx, limit=150)
        live = {d: ips for d, ips in resolved.items() if ips}
        resolver = _resolver(ctx)

        async def mx(d):
            try:
                return d, [r.exchange.to_text().rstrip(".") for r in await resolver.resolve(d, "MX")]
            except (dns.exception.DNSException, OSError):
                return d, []
        mxs = dict(await asyncio.gather(*(mx(d) for d in live)))
        ctx.progress(self.name, entity, len(perms), len(perms))
        ctx.log(f"lookalikes: {len(live)} of {len(perms)} permutations of {entity.value} are registered")
        for d, ips in sorted(live.items(), key=lambda kv: (not mxs.get(kv[0]), kv[0])):
            can_mail = bool(mxs.get(d))
            yield Finding(category="lookalike", title=perms[d], value=d, url=f"http://{d}", source=self.name,
                          target=entity, confidence=0.9,
                          data={"ips": ips, "mx": mxs.get(d), "severity": "medium" if can_mail else "low",
                                "note": "can receive email - phishing capable" if can_mail else ""})
