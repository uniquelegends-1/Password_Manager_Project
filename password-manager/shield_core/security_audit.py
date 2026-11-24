"""Security Intelligence Engine: Health Score, Risk Reasoning, Reuse Protection & Website Vulnerability Audit."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from shield_core.password_gen import calculate_entropy

if TYPE_CHECKING:
    from shield_core.vault_engine import VaultEntry

COMMON_WEAK_PASSWORDS = frozenset(
    {
        "123456", "12345678", "123456789", "1234567890", "password", "password1",
        "password123", "qwerty", "qwerty123", "abc123", "111111", "000000",
        "admin", "admin123", "letmein", "welcome", "monkey", "dragon", "baseball",
        "iloveyou", "trustno1", "sunshine", "princess", "football", "shadow",
        "superman", "michael", "master", "passw0rd", "p@ssword", "p@ssw0rd",
        "changeme", "default", "guest", "root", "test", "test1234", "qwertyuiop",
    }
)

KNOWN_SITE_ADVISORIES: dict[str, dict[str, str]] = {
    "yahoo.com": {"severity": "high", "year": "2013-2014", "summary": "Historic large-scale account breach (3B accounts).", "advice": "Rotate password if old and enable 2FA."},
    "linkedin.com": {"severity": "medium", "year": "2012 / 2021", "summary": "Historic hash leak (2012) & large profile scrape (2021).", "advice": "Ensure unique password and enable TOTP MFA."},
    "adobe.com": {"severity": "medium", "year": "2013", "summary": "153M user records & encrypted passwords exposed.", "advice": "Rotate password if unchanged since 2013 and enable 2FA."},
    "dropbox.com": {"severity": "medium", "year": "2012 / 2024", "summary": "2012 credential leak & 2024 Dropbox Sign unauthorized access.", "advice": "Use a unique strong password and enable TOTP MFA."},
    "canva.com": {"severity": "medium", "year": "2019", "summary": "137M user records exposed in 2019 breach.", "advice": "Rotate password if created before June 2019 and enable 2FA."},
    "lastpass.com": {"severity": "high", "year": "2022", "summary": "Encrypted customer vault backups stolen in 2022 breach.", "advice": "Rotate master password and all credentials previously stored there."},
    "myfitnesspal.com": {"severity": "medium", "year": "2018", "summary": "150M user accounts exposed in 2018 breach.", "advice": "Use a unique password not shared with other sites."},
    "zynga.com": {"severity": "medium", "year": "2019", "summary": "173M accounts compromised in 2019 breach.", "advice": "Ensure password is unique and recently rotated."},
    "trello.com": {"severity": "low", "year": "2024", "summary": "15M user emails scraped via API exposure.", "advice": "Watch for phishing and enable MFA."},
    "twitter.com": {"severity": "medium", "year": "2022", "summary": "API exposure leaked millions of email/phone mappings.", "advice": "Enable app-based TOTP MFA and use a unique password."},
    "x.com": {"severity": "medium", "year": "2022", "summary": "Historic Twitter API exposure increased phishing/credential-stuffing risk.", "advice": "Enable app-based TOTP MFA and use a unique password."},
    "ticketmaster.com": {"severity": "high", "year": "2024", "summary": "Large customer data breach reported in 2024.", "advice": "Rotate password immediately and monitor linked payment cards."},
    "att.com": {"severity": "high", "year": "2024", "summary": "Major customer dataset & call record exposures in 2024.", "advice": "Rotate password, add account PIN, and enable MFA."},
    "equifax.com": {"severity": "high", "year": "2017", "summary": "147M sensitive consumer records breached.", "advice": "Use a unique high-entropy password and MFA."},
    "marriott.com": {"severity": "medium", "year": "2018 / 2020", "summary": "Multiple Starwood/Marriott guest data breaches.", "advice": "Ensure unique password and monitor account activity."},
    "deezer.com": {"severity": "medium", "year": "2022", "summary": "200M+ user records exposed via third-party partner.", "advice": "Rotate password and avoid reuse."},
    "twitch.tv": {"severity": "medium", "year": "2021", "summary": "Major source code & creator payout data leak in 2021.", "advice": "Rotate stream keys/passwords and enable 2FA."},
    "roblox.com": {"severity": "medium", "year": "2023", "summary": "High-value phishing and account takeover target.", "advice": "Enable authenticator app 2FA and use a unique password."},
    "epicgames.com": {"severity": "medium", "year": "2019", "summary": "Frequent credential-stuffing target with prior SSO vulnerabilities.", "advice": "Enable TOTP 2FA and unique strong password."},
    "facebook.com": {"severity": "medium", "year": "2019 / 2021", "summary": "533M user phone/profile records leaked via scraping.", "advice": "Enable authenticator 2FA and check active login sessions."},
    "instagram.com": {"severity": "medium", "year": "2021", "summary": "Frequent phishing and credential-stuffing target.", "advice": "Enable authenticator 2FA (not SMS) and unique password."},
    "paypal.com": {"severity": "medium", "year": "2022", "summary": "Targeted by large-scale credential-stuffing campaigns.", "advice": "Critical financial account: require unique strong password + TOTP MFA."},
    "23andme.com": {"severity": "high", "year": "2023", "summary": "6.9M profiles exposed via credential stuffing of reused passwords.", "advice": "Never reuse passwords here and require 2FA."},
    "duolingo.com": {"severity": "low", "year": "2023", "summary": "2.6M user profile records scraped via API.", "advice": "Use a unique password and watch for phishing."},
    "reddit.com": {"severity": "medium", "year": "2018 / 2023", "summary": "2018 SMS 2FA bypass & 2023 employee phishing breach.", "advice": "Use app-based TOTP MFA (not SMS) and a unique password."},
}

HIGH_VALUE_CATEGORIES = frozenset({"Finance", "Email", "Work"})
CREDENTIAL_TYPES_REQUIRING_PASSWORD = frozenset({"Website", "Application", "Email", "Wi-Fi"})


@dataclass
class AuditFinding:
    code: str
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    title: str
    detail: str
    recommendation: str
    penalty: int


@dataclass
class EntryAuditResult:
    entry_id: str
    title: str
    entry_type: str
    username: str
    category: str
    url: str
    risk_score: int  # 0 (safe) .. 100 (critical)
    risk_level: str
    is_strong_password: bool
    findings: list[AuditFinding] = field(default_factory=list)


@dataclass
class WebsiteScanResult:
    url: str
    domain: str
    reachable: bool
    https_used: bool
    tls_version: str = ""
    cert_days_remaining: int | None = None
    missing_headers: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    error: str = ""


@dataclass
class VaultAuditReport:
    generated_at: str
    total_entries: int
    health_score: int  # 0..100
    risk_score: int  # 0..100
    risk_level: str
    strong_count: int
    reused_count: int
    weak_count: int
    breached_count: int
    vulnerable_site_count: int
    no_mfa_count: int
    stale_count: int
    reused_groups: list[list[str]]
    entry_results: list[EntryAuditResult]

    @property
    def potentially_exposed_count(self) -> int:
        return sum(
            1
            for r in self.entry_results
            if any(f.code in ("hibp_breach", "site_advisory", "http_url", "common_pwd") for f in r.findings)
        )

    def to_markdown(self) -> str:
        lines = [
            "# P.U.L.S.E. S.H.I.E.L.D. — Security Health & Risk Audit Report",
            "",
            f"- **Generated:** {self.generated_at}",
            f"- **Total Entries:** {self.total_entries}",
            f"- **Vault Health Score:** {self.health_score}/100",
            f"- **Overall Risk Score:** {self.risk_score}/100 ({self.risk_level} Risk)",
            "",
            "## Executive Dashboard",
            f"- Strong passwords: **{self.strong_count}**",
            f"- Reused passwords: **{self.reused_count}**",
            f"- Weak or common passwords: **{self.weak_count}**",
            f"- Potentially exposed accounts: **{self.potentially_exposed_count}**",
            f"- Breached passwords (HIBP): **{self.breached_count}**",
            f"- Website vulnerabilities / advisories: **{self.vulnerable_site_count}**",
            f"- Accounts without 2FA / Passkey: **{self.no_mfa_count}**",
            f"- Stale passwords (> 180 days): **{self.stale_count}**",
            "",
        ]
        if self.reused_groups:
            lines.append("## Password Reuse Groups")
            for idx, group in enumerate(self.reused_groups, 1):
                lines.append(f"{idx}. Shared across: {', '.join(group)}")
            lines.append("")

        lines.append("## Priority-Ranked Vulnerable Accounts")
        for rank, res in enumerate(self.entry_results, 1):
            if not res.findings:
                continue
            lines.append(
                f"### #{rank}. {res.title} [{res.entry_type} / {res.category}] — Risk {res.risk_score}/100 ({res.risk_level})"
            )
            if res.url:
                lines.append(f"- URL: `{res.url}`")
            for f in res.findings:
                lines.append(f"- **[{f.severity.upper()}] {f.title}:** {f.detail}")
                lines.append(f"  - *Recommendation:* {f.recommendation}")
            lines.append("")
        return "\n".join(lines)


def extract_domain(url: str) -> str:
    raw = url.strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def match_known_site_advisory(url: str) -> tuple[str, dict[str, str]] | None:
    host = extract_domain(url)
    if not host:
        return None
    if host in KNOWN_SITE_ADVISORIES:
        return host, KNOWN_SITE_ADVISORIES[host]
    parts = host.split(".")
    if len(parts) >= 2:
        root = ".".join(parts[-2:])
        if root in KNOWN_SITE_ADVISORIES:
            return root, KNOWN_SITE_ADVISORIES[root]
    return None


def check_password_reuse(
    entries: list[VaultEntry],
    candidate_password: str,
    exclude_entry_id: str | None = None,
) -> list[VaultEntry]:
    if not candidate_password:
        return []
    return [
        e
        for e in entries
        if (not exclude_entry_id or e.id != exclude_entry_id)
        and e.password
        and e.password == candidate_password
    ]


def find_reused_password_groups(entries: list[VaultEntry]) -> dict[str, list[VaultEntry]]:
    buckets: dict[str, list[VaultEntry]] = {}
    for entry in entries:
        if not entry.password:
            continue
        buckets.setdefault(entry.password, []).append(entry)
    return {pwd: items for pwd, items in buckets.items() if len(items) > 1}


def check_hibp_pwned(password: str, timeout: float = 6.0) -> int:
    """Have I Been Pwned k-Anonymity check (sends only first 5 SHA-1 hex chars)."""
    if not password:
        return 0
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "PULSE-SHIELD-Vault/3.0", "Add-Padding": "true"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="ignore")
    for line in body.splitlines():
        if ":" not in line:
            continue
        h_suffix, count_str = line.split(":", 1)
        if h_suffix.strip().upper() == suffix:
            try:
                return int(count_str.strip())
            except ValueError:
                return 1
    return 0


def _is_public_host(host: str) -> bool:
    if not host or host == "localhost":
        return False
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        return bool(infos)
    except OSError:
        return False


class _SafePublicRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent SSRF by validating that every HTTP redirect hop targets a public http/https host."""

    max_redirections = 3

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlparse(newurl)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        if scheme not in ("http", "https") or not _is_public_host(host):
            raise urllib.error.URLError("Blocked unsafe redirect to private or non-HTTP host.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def scan_website_security(url: str, timeout: float = 5.0) -> WebsiteScanResult:
    raw = url.strip()
    if not raw:
        return WebsiteScanResult(url=url, domain="", reachable=False, https_used=False, error="No URL")

    normalized = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(normalized)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()

    if scheme not in ("http", "https") or not host:
        return WebsiteScanResult(url=raw, domain=host, reachable=False, https_used=False, error="Unsupported URL")
    if not _is_public_host(host):
        return WebsiteScanResult(
            url=raw, domain=host, reachable=False, https_used=(scheme == "https"), error="Private/unresolvable host"
        )

    issues: list[str] = []
    missing_headers: list[str] = []
    https_used = scheme == "https"
    tls_version = ""
    cert_days_remaining: int | None = None

    if not https_used:
        issues.append("Saved URL uses unencrypted HTTP instead of HTTPS.")

    try:
        ctx = ssl.create_default_context()
        port = parsed.port or 443
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                tls_version = ssock.version() or ""
                if tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
                    issues.append(f"Deprecated TLS version detected: {tls_version}.")
                cert = ssock.getpeercert()
                if cert and "notAfter" in cert:
                    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    )
                    cert_days_remaining = (expires - datetime.now(timezone.utc)).days
                    if cert_days_remaining < 0:
                        issues.append("SSL/TLS certificate is expired.")
                    elif cert_days_remaining < 21:
                        issues.append(f"SSL/TLS certificate expires soon ({cert_days_remaining} days).")
    except ssl.SSLCertVerificationError as exc:
        issues.append(f"Invalid SSL/TLS certificate: {exc.verify_message}.")
    except Exception:
        if https_used:
            issues.append("Could not complete TLS handshake on HTTPS.")

    reachable = False
    headers_map: dict[str, str] = {}
    target_url = normalized if https_used else f"https://{host}{parsed.path or '/'}"
    opener = urllib.request.build_opener(_SafePublicRedirectHandler())
    for method in ("HEAD", "GET"):
        req = urllib.request.Request(
            target_url, method=method, headers={"User-Agent": "PULSE-SHIELD-Audit/3.0"}
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                reachable = True
                headers_map = {k.lower(): v for k, v in resp.headers.items()}
                break
        except urllib.error.HTTPError as err:
            reachable = True
            headers_map = {k.lower(): v for k, v in err.headers.items()}
            if method == "HEAD" and err.code == 405:
                continue
            break
        except Exception:
            break

    if reachable:
        for key, label in (
            ("strict-transport-security", "HSTS"),
            ("content-security-policy", "CSP"),
            ("x-content-type-options", "X-Content-Type-Options"),
            ("x-frame-options", "X-Frame-Options"),
        ):
            if key not in headers_map:
                missing_headers.append(label)
        if "strict-transport-security" not in headers_map:
            issues.append("Missing Strict-Transport-Security (HSTS) header.")
        if "content-security-policy" not in headers_map and "x-frame-options" not in headers_map:
            issues.append("Missing both CSP and X-Frame-Options headers (clickjacking/XSS exposure).")

    return WebsiteScanResult(
        url=raw,
        domain=host,
        reachable=reachable,
        https_used=https_used,
        tls_version=tls_version,
        cert_days_remaining=cert_days_remaining,
        missing_headers=missing_headers,
        issues=issues,
    )


def _parse_utc(ts: str) -> datetime | None:
    if not ts:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S.%f UTC", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _risk_level(risk_score: int) -> str:
    if risk_score >= 65:
        return "Critical"
    if risk_score >= 40:
        return "High"
    if risk_score >= 18:
        return "Moderate"
    return "Low"


def audit_vault(
    entries: list[VaultEntry],
    hibp_counts: dict[str, int] | None = None,
    web_scans: dict[str, WebsiteScanResult] | None = None,
    stale_days: int = 180,
) -> VaultAuditReport:
    now = datetime.now(timezone.utc)
    reused_map = find_reused_password_groups(entries)
    reused_ids = {e.id for group in reused_map.values() for e in group}
    hibp_counts = hibp_counts or {}
    web_scans = web_scans or {}

    entry_results: list[EntryAuditResult] = []
    strong_count = 0
    weak_count = 0
    breached_count = 0
    vulnerable_site_count = 0
    no_mfa_count = 0
    stale_count = 0

    for entry in entries:
        findings: list[AuditFinding] = []
        pwd = entry.password or ""
        pwd_lower = pwd.lower()
        entry_type = getattr(entry, "entry_type", "Website")
        needs_pwd = entry_type in CREDENTIAL_TYPES_REQUIRING_PASSWORD
        is_strong = False

        # 1. Password strength & reasoning
        if not pwd:
            if needs_pwd:
                weak_count += 1
                findings.append(
                    AuditFinding(
                        "empty_pwd",
                        "critical",
                        "Missing password",
                        "No password is stored for this login credential.",
                        "Generate a unique 20+ character password using S.H.I.E.L.D. Generator.",
                        45,
                    )
                )
        else:
            entropy = calculate_entropy(pwd)
            is_common = pwd_lower in COMMON_WEAK_PASSWORDS
            user_part = entry.username.split("@")[0].lower() if entry.username else ""
            contains_user = len(user_part) >= 4 and user_part in pwd_lower

            if is_common:
                weak_count += 1
                findings.append(
                    AuditFinding(
                        "common_pwd",
                        "critical",
                        "Common leaked dictionary password",
                        "Matches a top commonly cracked password targeted first in automated attacks.",
                        "Replace immediately with a random 20+ character password.",
                        45,
                    )
                )
            elif len(pwd) < 8 or entropy < 32:
                weak_count += 1
                findings.append(
                    AuditFinding(
                        "weak_pwd",
                        "high",
                        "Weak password entropy",
                        f"Only {len(pwd)} chars ({entropy:.0f} bits entropy) — vulnerable to fast offline GPU cracking.",
                        "Use at least 16 random characters with letters, numbers, and symbols.",
                        32,
                    )
                )
            elif len(pwd) < 12 or entropy < 48:
                weak_count += 1
                findings.append(
                    AuditFinding(
                        "fair_pwd",
                        "medium",
                        "Below-recommended strength",
                        f"Moderate strength ({len(pwd)} chars, {entropy:.0f} bits entropy).",
                        "Upgrade to a 20+ character password or 5-word passphrase.",
                        15,
                    )
                )
            elif entropy >= 72 and entry.id not in reused_ids and not contains_user:
                is_strong = True
                strong_count += 1

            if contains_user:
                findings.append(
                    AuditFinding(
                        "user_in_pwd",
                        "medium",
                        "Password contains username",
                        "Includes part of your username/email, dramatically shrinking attacker search space.",
                        "Generate an unrelated random password.",
                        12,
                    )
                )

        # 2. Password Reuse
        if entry.id in reused_ids:
            others = [e.title for e in reused_map[entry.password] if e.id != entry.id]
            findings.append(
                AuditFinding(
                    "reused_pwd",
                    "high",
                    "Reused password across accounts",
                    f"Identical password shared with {len(others)} other account(s): {', '.join(others[:4])}. "
                    "A breach on any one site exposes every linked account via credential stuffing.",
                    "Generate a unique password for each account.",
                    28,
                )
            )

        # 3. HIBP Breach Exposure
        pwned = hibp_counts.get(entry.id, 0)
        if pwned > 0:
            breached_count += 1
            findings.append(
                AuditFinding(
                    "hibp_breach",
                    "critical",
                    "Password found in known data breaches",
                    f"Matched {pwned:,} exposure(s) via HIBP k-Anonymity check.",
                    "Change this password immediately on the website and enable 2FA.",
                    45,
                )
            )

        # 4. Website Protocol / Homograph / Known Breach Advisory / Live Scan
        site_flagged = False
        url = (entry.url or "").strip()
        if url:
            if url.lower().startswith("http://"):
                site_flagged = True
                findings.append(
                    AuditFinding(
                        "http_url",
                        "high",
                        "Unencrypted HTTP website",
                        "Uses http:// instead of https:// — credentials can be intercepted on shared networks.",
                        "Switch the URL to https:// and verify the site supports TLS.",
                        22,
                    )
                )
            domain = extract_domain(url)
            if "xn--" in domain:
                site_flagged = True
                findings.append(
                    AuditFinding(
                        "punycode_url",
                        "high",
                        "Punycode / lookalike domain",
                        f"Domain '{domain}' uses internationalized Punycode, commonly abused in phishing.",
                        "Verify the legitimate website domain before signing in.",
                        24,
                    )
                )
            try:
                ipaddress.ip_address(domain)
                site_flagged = True
                findings.append(
                    AuditFinding(
                        "ip_url",
                        "medium",
                        "Raw IP login address",
                        f"Logs into raw IP '{domain}' without a domain certificate identity.",
                        "Use a verified HTTPS hostname where possible.",
                        10,
                    )
                )
            except ValueError:
                pass

            adv_match = match_known_site_advisory(url)
            if adv_match:
                matched_domain, adv = adv_match
                site_flagged = True
                sev = adv["severity"]
                pen = {"high": 18, "medium": 12, "low": 6}.get(sev, 8)
                findings.append(
                    AuditFinding(
                        "site_advisory",
                        sev,
                        f"Known breached/high-risk service ({matched_domain}, {adv['year']})",
                        adv["summary"],
                        adv["advice"],
                        pen,
                    )
                )

            scan = web_scans.get(entry.id)
            if scan and scan.issues:
                site_flagged = True
                sev = "high" if any("SSL" in i or "HTTP" in i or "TLS" in i for i in scan.issues) else "medium"
                findings.append(
                    AuditFinding(
                        "live_web_scan",
                        sev,
                        f"Live site vulnerability check ({scan.domain})",
                        " ".join(scan.issues),
                        "Prefer strong unique password + MFA on sites lacking modern security headers/TLS.",
                        18 if sev == "high" else 10,
                    )
                )

        if site_flagged:
            vulnerable_site_count += 1

        # 5. MFA / Passkey coverage
        has_totp = bool(getattr(entry, "totp_secret", ""))
        has_passkey = bool(getattr(entry, "passkey_enabled", False))
        if needs_pwd and not has_totp and not has_passkey:
            no_mfa_count += 1
            is_hv = entry.category in HIGH_VALUE_CATEGORIES
            findings.append(
                AuditFinding(
                    "no_mfa",
                    "medium" if is_hv else "low",
                    "No 2FA / TOTP or Passkey configured",
                    f"{entry.category} account relies on password alone without a second factor.",
                    "Enable TOTP 2FA (or a Passkey) on the service and store the TOTP secret here.",
                    12 if is_hv else 5,
                )
            )

        # 6. Stale password
        if pwd:
            pwd_ts = _parse_utc(getattr(entry, "password_updated_at", "") or entry.updated_at or entry.created_at)
            if pwd_ts is not None:
                age_days = (now - pwd_ts).days
                if age_days >= stale_days:
                    stale_count += 1
                    findings.append(
                        AuditFinding(
                            "stale_pwd",
                            "low",
                            f"Old password ({age_days} days)",
                            f"Password has not been updated in {age_days} days.",
                            "Consider rotating credentials on sensitive accounts periodically.",
                            8,
                        )
                    )

        entry_risk = min(100, sum(f.penalty for f in findings))
        entry_results.append(
            EntryAuditResult(
                entry_id=entry.id,
                title=entry.title,
                entry_type=entry_type,
                username=entry.username,
                category=entry.category,
                url=entry.url,
                risk_score=entry_risk,
                risk_level=_risk_level(entry_risk),
                is_strong_password=is_strong,
                findings=findings,
            )
        )

    entry_results.sort(key=lambda r: (-r.risk_score, r.title.lower()))

    if not entries:
        overall_risk = 0
        overall_health = 100
    else:
        avg_risk = sum(r.risk_score for r in entry_results) / len(entry_results)
        max_risk = max(r.risk_score for r in entry_results)
        overall_risk = min(100, int(round(0.7 * avg_risk + 0.3 * max_risk)))
        overall_health = max(0, 100 - overall_risk)

    reused_groups = [[e.title for e in group] for group in reused_map.values()]
    return VaultAuditReport(
        generated_at=now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        total_entries=len(entries),
        health_score=overall_health,
        risk_score=overall_risk,
        risk_level=_risk_level(overall_risk),
        strong_count=strong_count,
        reused_count=len(reused_ids),
        weak_count=weak_count,
        breached_count=breached_count,
        vulnerable_site_count=vulnerable_site_count,
        no_mfa_count=no_mfa_count,
        stale_count=stale_count,
        reused_groups=reused_groups,
        entry_results=entry_results,
    )
