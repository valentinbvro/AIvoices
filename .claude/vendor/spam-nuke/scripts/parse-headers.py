#!/usr/bin/env python3
"""
parse-headers.py — Extract a spammer's sending infrastructure from a raw email.
Usage: parse-headers.py [--no-dns] <message.eml>
       cat message.eml | parse-headers.py [--no-dns] -

Identifies: mailbox provider (Google Workspace / Microsoft 365 / Gmail / Outlook),
ESP fingerprint, sequencer (via tracking-link CNAMEs, needs `dig` unless --no-dns),
link hosts, sending IPs, authentication results, company confidence, abuse contacts.
Python 3 standard library only.
"""

import sys
import re
import email
import ipaddress
import shutil
import subprocess
from email.policy import default as default_policy

ESP_SIGNATURES = {
    # Header patterns → ESP name + abuse contact
    "sendgrid.net": ("SendGrid", "abuse@sendgrid.com"),
    "X-SG-EID": ("SendGrid", "abuse@sendgrid.com"),
    "X-SG-ID": ("SendGrid", "abuse@sendgrid.com"),
    "mailgun.org": ("Mailgun", "abuse@mailgun.com"),
    "X-Mailgun": ("Mailgun", "abuse@mailgun.com"),
    "amazonses.com": ("AWS SES", "email-abuse@amazon.com"),
    "X-SES-Outgoing": ("AWS SES", "email-abuse@amazon.com"),
    "postmarkapp.com": ("Postmark", "support@postmarkapp.com"),
    "X-PM-Message-Id": ("Postmark", "support@postmarkapp.com"),
    "mcsv.net": ("Mailchimp", "abuse@mailchimp.com"),
    "mcdlv.net": ("Mailchimp", "abuse@mailchimp.com"),
    "X-MC-User": ("Mailchimp", "abuse@mailchimp.com"),
    "hubspotemail.net": ("HubSpot", "abuse@hubspot.com"),
    "ccsend.com": ("Constant Contact", "abuse@constantcontact.com"),
    "sendinblue.com": ("Brevo", "abuse@brevo.com"),
    "brevo.com": ("Brevo", "abuse@brevo.com"),
    "sparkpostmail.com": ("SparkPost", "abuse@sparkpost.com"),
    "klaviyomail.com": ("Klaviyo", "compliance@klaviyo.com"),
    "activecampaign.com": ("ActiveCampaign", "abuse@activecampaign.com"),
    "cio.email": ("Customer.io", "support@customer.io"),
    "resend.dev": ("Resend", "support@resend.com"),
    "instantly.ai": ("Instantly", "support@instantly.ai"),
    "mixmax.com": ("Mixmax", "support@mixmax.com"),
    "outreach.io": ("Outreach", "abuse@outreach.io"),
    "salesloft.com": ("Salesloft", "abuse@salesloft.com"),
    "reply.io": ("Reply.io", "support@reply.io"),
    "lemlist.com": ("Lemlist", "support@lemlist.com"),
    "woodpecker.co": ("Woodpecker", "support@woodpecker.co"),
    "smartlead.ai": ("Smartlead", "support@smartlead.ai"),
    "mailshake.com": ("Mailshake", "support@mailshake.com"),
    "apollo.io": ("Apollo", "support@apollo.io"),
    "freshworks.com": ("Freshworks", "support@freshworks.com"),
    "dm.aliyun.com": ("Alibaba Cloud DirectMail",
                      "Alibaba Cloud Reporting Center / Abuse Claim Form (DirectMail policy bans unsolicited email; "
                      "third-party complaints can permanently ban the account)"),
    "aliyuncs.com": ("Alibaba Cloud DirectMail",
                     "Alibaba Cloud Reporting Center / Abuse Claim Form (DirectMail policy bans unsolicited email; "
                     "third-party complaints can permanently ban the account)"),
    ".263.net": ("Net263 hosted mail (China)", "abuse@link263.com (per a 263 reseller page; verify)"),
    "exacttarget.com": ("Salesforce Marketing Cloud", "https://security.salesforce.com/report-concern-form (Platform Abuse → Unsolicited Commercial Emails)"),
    "pardot.com": ("Salesforce Pardot / Account Engagement", "https://security.salesforce.com/report-concern-form (Platform Abuse → Unsolicited Commercial Emails)"),
    "elasticemail.com": ("Elastic Email", "https://elasticemail.com/report-spam"),
    "rsgsv.net": ("Mailchimp", "abuse@mailchimp.com"),
}

# Freemail / hosted inboxes used as Reply-To → where to report the address
FREEMAIL_ABUSE = {
    "gmail.com": "https://support.google.com/mail/contact/abuse",
    "googlemail.com": "https://support.google.com/mail/contact/abuse",
    "outlook.com": "abuse@outlook.com", "hotmail.com": "abuse@outlook.com",
    "live.com": "abuse@outlook.com", "msn.com": "abuse@outlook.com",
    "tutamail.com": "abuse@tutao.de", "tutanota.com": "abuse@tutao.de", "tuta.io": "abuse@tutao.de",
    "tuta.com": "abuse@tutao.de",
    "qq.com": "spam@qq.com (Tencent's spam-report inbox)",
}

# Sending-server hostname (from the trusted hop) → provider
SENDING_SERVER_PATTERNS = [
    (r"\.dm\.aliyun\.com$", "Alibaba Cloud DirectMail"),
    (r"\.263\.net$", "Net263 hosted mail (China)"),
    (r"^mail-[\w-]+\.google\.com$", "Google (Gmail / Workspace)"),
    (r"\.outbound\.protection\.outlook\.com$", "Microsoft 365 / Outlook"),
    (r"\.amazonses\.com$", "Amazon SES"),
    (r"\.sendgrid\.net$", "SendGrid"),
    (r"\.mailgun\.(org|net)$", "Mailgun"),
    (r"\.mcsv\.net$|\.mcdlv\.net$", "Mailchimp"),
    (r"\.sparkpostmail\.com$", "SparkPost"),
    (r"\.zoho\.com$|\.zohomail\.com$", "Zoho Mail"),
    (r"\.exacttarget\.com$", "Salesforce Marketing Cloud"),
    (r"\.rsgsv\.net$", "Mailchimp"),
    (r"elasticemail", "Elastic Email"),
]

# Platforms abused to HOST payloads (phishing pages, redirectors). Not the spammer's brand:
# report the exact URL to the platform's abuse channel + Google Safe Browsing.
ABUSED_HOSTING = [
    ("storage.googleapis.com", "Google Cloud Storage",
     "https://support.google.com/code/contact/cloud_platform_report (+ Safe Browsing report_phish)"),
    ("firebasestorage.googleapis.com", "Firebase Storage (Google)",
     "https://support.google.com/code/contact/cloud_platform_report"),
    (".web.app", "Firebase Hosting (Google)", "https://support.google.com/code/contact/cloud_platform_report"),
    (".firebaseapp.com", "Firebase Hosting (Google)", "https://support.google.com/code/contact/cloud_platform_report"),
    ("docs.google.com", "Google Docs/Forms", "'Report abuse' link on the document + Safe Browsing"),
    ("forms.gle", "Google Forms", "'Report abuse' link on the form"),
    ("sites.google.com", "Google Sites", "'Report abuse' link on the site"),
    ("blob.core.windows.net", "Azure Blob Storage", "https://msrc.microsoft.com/report/abuse"),
    ("web.core.windows.net", "Azure Static Web", "https://msrc.microsoft.com/report/abuse"),
    ("amazonaws.com", "AWS (S3/other)", "abuse@amazonaws.com / AWS abuse form"),
    ("cloudfront.net", "AWS CloudFront", "abuse@amazonaws.com / AWS abuse form"),
    (".r2.dev", "Cloudflare R2", "https://abuse.cloudflare.com"),
    (".pages.dev", "Cloudflare Pages", "https://abuse.cloudflare.com"),
    (".workers.dev", "Cloudflare Workers", "https://abuse.cloudflare.com"),
    (".github.io", "GitHub Pages", "https://github.com/contact/report-abuse"),
    ("raw.githubusercontent.com", "GitHub", "https://github.com/contact/report-abuse"),
    (".vercel.app", "Vercel", "https://vercel.com/abuse"),
    (".netlify.app", "Netlify", "abuse@netlify.com"),
    ("ipfs.", "IPFS gateway", "the gateway operator's abuse contact"),
]

# Common platforms that appear in links but are never the spammer's brand domain
COMMON_PLATFORMS = (
    "google.com", "gmail.com", "googleapis.com", "outlook.com", "microsoft.com", "office.com",
    "linkedin.com", "github.com", "calendly.com", "zoom.us", "youtube.com", "youtu.be",
    "twitter.com", "x.com", "facebook.com", "instagram.com", "t.me", "wa.me", "whatsapp.com",
    "apple.com", "bit.ly", "aliyuncs.com", "w3.org", "schema.org", "qq.com",
)


# Sequencers / platforms identified from tracking-link hosts.
# CNAME targets come from each vendor's own custom-tracking-domain setup docs.
SEQUENCER_CNAME_TARGETS = {
    "prox.itrackly.com": ("Instantly", "support@instantly.ai"),
    "open.sleadtrack.com": ("Smartlead", "support@smartlead.ai"),
    "custom.lemlist.com": ("lemlist", "support@lemlist.com"),
    "sendgrid.net": ("SendGrid", "abuse@sendgrid.com"),
    "mailgun.org": ("Mailgun", "abuse@mailgun.com"),
    "go.pardot.com": ("Salesforce Pardot / Account Engagement", "https://security.salesforce.com/report-concern-form (Platform Abuse → Unsolicited Commercial Emails)"),
    "api.elasticemail.com": ("Elastic Email", "https://elasticemail.com/report-spam"),
}
# Shared (non-custom) tracking hosts that name the platform directly.
SEQUENCER_HOST_PATTERNS = {
    "inreg1.com": ("Instantly (shared tracking domain)", "support@instantly.ai"),
    "itrackly.com": ("Instantly", "support@instantly.ai"),
    "sleadtrack.com": ("Smartlead", "support@smartlead.ai"),
    "lemlist.com": ("lemlist", "support@lemlist.com"),
    "list-manage.com": ("Mailchimp", "abuse@mailchimp.com"),
    "hubspotlinks.com": ("HubSpot", "abuse@hubspot.com"),
    "klclick": ("Klaviyo", "compliance@klaviyo.com"),
    "ct.sendgrid.net": ("SendGrid", "abuse@sendgrid.com"),
}
# Hostname prefixes vendors use for custom tracking subdomains (inst., smart., …).
TRACKING_PREFIXES = ("inst.", "smart.", "emailtracking.", "track.", "tracking.",
                     "link.", "links.", "click.", "clicks.", "go.", "trail.",
                     "route.", "lemtrail.", "email.", "em.", "url.", "t.")

GOOGLE_CONSUMER = {"gmail.com", "googlemail.com"}
MS_CONSUMER = {"outlook.com", "hotmail.com", "live.com", "msn.com"}

URL_HOST_RE = re.compile(r"https?://([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})", re.I)


def _collect_bodies(msg) -> tuple:
    """Return (plain_text, html_text) concatenated across all parts."""
    plain, html = [], []
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        ct = part.get_content_type()
        if ct not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else str(payload)
        (plain if ct == "text/plain" else html).append(content or "")
    return "\n".join(plain), "\n".join(html)


def _extract_link_hosts(*texts) -> list:
    hosts = []
    for t in texts:
        for h in URL_HOST_RE.findall(t or ""):
            h = h.lower().rstrip(".")
            if h not in hosts:
                hosts.append(h)
    return hosts[:40]


def _dig_cname(host: str) -> str:
    try:
        out = subprocess.run(["dig", "+short", "CNAME", host], capture_output=True,
                             text=True, timeout=6).stdout.strip()
        return out.splitlines()[0].rstrip(".").lower() if out else ""
    except Exception:
        return ""


def detect_sequencers(link_hosts: list, use_dns: bool) -> list:
    """Identify the sending platform behind tracking links."""
    found = []
    can_dig = use_dns and shutil.which("dig") is not None
    for host in link_hosts:
        hit = None
        for pat, (name, abuse) in SEQUENCER_HOST_PATTERNS.items():
            if pat in host:
                hit = {"host": host, "via": f"host contains {pat}", "name": name, "abuse": abuse}
                break
        if not hit and can_dig and host.startswith(TRACKING_PREFIXES):
            target = _dig_cname(host)
            if target:
                for t, (name, abuse) in SEQUENCER_CNAME_TARGETS.items():
                    if target == t or target.endswith("." + t):
                        hit = {"host": host, "via": f"CNAME → {target}", "name": name, "abuse": abuse}
                        break
                if not hit:
                    hit = {"host": host, "via": f"CNAME → {target}", "name": None,
                           "abuse": "unknown — search the CNAME target to identify the platform"}
        if hit and hit not in found:
            found.append(hit)
    return found


def detect_mailbox_provider(msg, from_domain: str, dkim_domains: list) -> dict:
    """Detect whether the message was sent from Google or Microsoft mailboxes.

    Only sender-side evidence counts: the recipient's own provider adds its own
    headers, so match the *sending* hop (Received: from mail-*.google.com /
    *.outbound.protection.outlook.com) and the sender's DKIM, not X-MS-Exchange-*.
    """
    received = " ".join(msg.get_all("Received", []) or [])
    google = bool(re.search(r"from mail-[\w-]+\.google\.com", received, re.I)) \
        or msg.get("X-Gm-Message-State") is not None
    microsoft = bool(re.search(r"from \S+\.outbound\.protection\.outlook\.com", received, re.I)) \
        or any(d.lower().endswith(".onmicrosoft.com") for d in dkim_domains)
    if google:
        if from_domain in GOOGLE_CONSUMER:
            return {"provider": "Gmail (consumer account)",
                    "abuse": "https://support.google.com/mail/contact/abuse"}
        return {"provider": "Google Workspace (custom domain)",
                "abuse": f"abuse@{from_domain} (Google monitors abuse@/postmaster@ on every Workspace domain) "
                         f"+ https://support.google.com/mail/contact/abuse"}
    if microsoft:
        if from_domain in MS_CONSUMER:
            return {"provider": "Outlook.com (consumer account)", "abuse": "abuse@outlook.com"}
        return {"provider": "Microsoft 365 tenant",
                "abuse": "abuse@outlook.com (Microsoft may redirect tenant abuse — follow its reply)"}
    return {}


def trusted_sending_hop(msg) -> dict:
    """The topmost Received header with a 'from ... [IP]' clause was written by the
    recipient's own mail server (e.g. 'by mx.google.com') — the trust boundary. Its
    'from' host/IP is the real sending server. Everything below it is the sender's
    own claim and can be forged."""
    for r in msg.get_all("Received", []) or []:
        m = re.search(r"from\s+(\S+)\s+\(([^)]*?)\[?(\d{1,3}(?:\.\d{1,3}){3})\]?\)", r)
        if m:
            helo, rdns_part, ip = m.group(1), m.group(2), m.group(3)
            rdns = (rdns_part.split()[0] if rdns_part.split() else helo).rstrip(".").lower()
            provider = None
            for pat, name in SENDING_SERVER_PATTERNS:
                if re.search(pat, rdns):
                    provider = name
                    break
            by = re.search(r"\bby\s+(\S+)", r)
            return {"helo": helo.rstrip(".").lower(), "rdns": rdns, "ip": ip, "provider": provider,
                    "by": by.group(1) if by else "",
                    "mismatch": not rdns.endswith(".".join(helo.rstrip(".").lower().split(".")[-2:]))}
    return {}


def abused_hosting(plain: str, html: str) -> list:
    hits = []
    for url in re.findall(r"https?://[^\s\"'<>)]+", (plain or "") + " " + (html or "")):
        host = re.sub(r"^https?://", "", url).split("/")[0].lower()
        for pat, name, channel in ABUSED_HOSTING:
            if (pat.startswith(".") and host.endswith(pat)) or (not pat.startswith(".") and pat in host):
                entry = {"url": url[:200], "platform": name, "report": channel}
                if entry not in hits:
                    hits.append(entry)
                break
    return hits[:15]


def _tld_exists(domain: str) -> bool:
    """True unless dig confirms the TLD has no NS records (e.g. '.htl')."""
    tld = domain.rsplit(".", 1)[-1]
    if not tld or shutil.which("dig") is None:
        return True
    try:
        out = subprocess.run(["dig", "+short", "NS", tld + "."], capture_output=True, text=True,
                             timeout=6).stdout.strip()
        return bool(out)
    except Exception:
        return True


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_unspecified)


def parse_headers(raw: str, use_dns: bool = True) -> dict:
    """Parse raw email headers and extract infrastructure info."""
    # Try parsing as full email first, fall back to headers-only
    msg = email.message_from_string(raw, policy=default_policy)

    result = {
        "from": msg.get("From", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "message_id": msg.get("Message-ID", ""),
        "subject": msg.get("Subject", ""),
        "list_unsubscribe": msg.get("List-Unsubscribe", ""),
        "sending_ips": [],
        "received_chain": [],
        "dkim_domains": [],
        "esps_detected": [],
        "auth_results": msg.get("Authentication-Results", ""),
        "spf_result": "",
        "dkim_result": "",
        "dmarc_result": "",
        "x_headers": {},
        "body_snippet": "",
        "company_id": {},  # Company identification + confidence
    }

    # Extract Received headers (reverse order = sending path)
    received_headers = msg.get_all("Received", [])
    for r in received_headers:
        result["received_chain"].append(r.strip())
        # Extract IPs
        ips = re.findall(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", r)
        result["sending_ips"].extend(ips)

    # Deduplicate IPs, remove private/loopback/link-local ranges
    # (only 172.16.0.0/12 is private — 172.0–15 and 172.32+ are public)
    result["sending_ips"] = list(dict.fromkeys(
        ip for ip in result["sending_ips"]
        if _is_public_ip(ip)
    ))

    # Extract DKIM signing domains
    dkim_headers = msg.get_all("DKIM-Signature", [])
    for dkim in dkim_headers:
        d_match = re.search(r"d=([^\s;]+)", dkim)
        if d_match:
            result["dkim_domains"].append(d_match.group(1))

    # Parse Authentication-Results
    auth = result["auth_results"]
    if auth:
        spf_match = re.search(r"spf=(\w+)", auth)
        dkim_match = re.search(r"dkim=(\w+)", auth)
        dmarc_match = re.search(r"dmarc=(\w+)", auth)
        if spf_match:
            result["spf_result"] = spf_match.group(1)
        if dkim_match:
            result["dkim_result"] = dkim_match.group(1)
        if dmarc_match:
            result["dmarc_result"] = dmarc_match.group(1)

    # Collect X- headers
    for key in msg.keys():
        if key.startswith("X-"):
            result["x_headers"][key] = msg.get(key, "")

    # Detect ESPs from all header content
    all_headers_str = raw
    seen_esps = set()
    for pattern, (esp_name, abuse_contact) in ESP_SIGNATURES.items():
        if pattern in all_headers_str and esp_name not in seen_esps:
            result["esps_detected"].append({
                "name": esp_name,
                "abuse_contact": abuse_contact,
                "matched_on": pattern,
            })
            seen_esps.add(esp_name)

    # Extract body snippet for company identification
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                try:
                    result["body_snippet"] = part.get_content()[:1000]
                except Exception:
                    pass
                break
    else:
        try:
            result["body_snippet"] = msg.get_content()[:1000] if hasattr(msg, 'get_content') else ""
        except Exception:
            result["body_snippet"] = msg.get_payload(decode=True, errors="replace")[:1000] if msg.get_payload() else ""

    # Full bodies (text + HTML) for link hosts; HTML-only mail gets a text snippet too
    plain, html = _collect_bodies(msg)
    _vis = plain or re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html or "")
    _vis = re.sub(r"<[^>]+>", " ", _vis)
    _vis = re.sub(r"&nbsp;|&#160;", " ", _vis)
    _vis = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), _vis)
    result["intro"] = " ".join(_vis.split())[:240]
    if not result["body_snippet"] and html:
        result["body_snippet"] = html[:3000]  # raw HTML keeps href URLs for body signals
    result["link_hosts"] = _extract_link_hosts(plain, html)
    unsub_hosts = _extract_link_hosts(str(result["list_unsubscribe"] or ""))
    result["sequencers"] = detect_sequencers(
        result["link_hosts"] + [h for h in unsub_hosts if h not in result["link_hosts"]], use_dns)

    # b) Abuse channels the sending platform embedded in the message itself
    result["abuse_headers"] = []
    for k, v in msg.items():
        kl = k.lower()
        if "abuse" in kl or "complain" in kl or kl in ("feedback-id", "x-feedback-id"):
            entry = (k, " ".join(str(v).split())[:220])
            if entry not in result["abuse_headers"]:
                result["abuse_headers"].append(entry)
    result["abuse_links"] = []
    for u in re.findall(r"https?://[^\s\"'<>)]+", (plain or "") + " " + (html or "")):
        if re.search(r"report[-_]?abuse|abuse[-_]?report|/contact/abuse|/abuse(?:[/?]|$)", u, re.I):
            if u[:220] not in result["abuse_links"]:
                result["abuse_links"].append(u[:220])

    from_match = re.search(r"@([\w.-]+)", result["from"] or "")
    from_domain = from_match.group(1).lower() if from_match else ""
    result["mailbox_provider"] = detect_mailbox_provider(msg, from_domain, result["dkim_domains"])
    result["from_domain"] = from_domain
    result["trusted_hop"] = trusted_sending_hop(msg)
    result["abused_hosting"] = abused_hosting(plain, html)

    rt = re.search(r"@([\w.-]+)", result["reply_to"] or "")
    result["reply_to_domain"] = rt.group(1).lower() if rt else ""

    # Phishing tells: display name impersonating the recipient; forged From domain
    flags = []
    to_addr = (msg.get("Delivered-To") or msg.get("To") or "").lower()
    to_m = re.search(r"([\w.+-]+)@([\w.-]+)", to_addr)
    disp = re.match(r'\s*"?([^"<]*)"?\s*<', result["from"] or "")
    if to_m and disp:
        name = disp.group(1).strip().lower()
        if name and (name == to_m.group(1) or to_m.group(0) in name):
            flags.append(f"From display name '{disp.group(1).strip()}' impersonates the recipient "
                         f"({to_m.group(0)}) — phishing tell")
    if from_domain and use_dns and not _tld_exists(from_domain):
        flags.append(f"From domain '{from_domain}' uses a TLD that does not exist — the From is forged. "
                     f"Don't report it; report the authenticated domains (DKIM d=, Return-Path) and the sending IP")
    result["flags"] = flags
    result["forged_from"] = any("TLD that does not exist" in f for f in flags)

    platform_markers = tuple(SEQUENCER_HOST_PATTERNS) + tuple(SEQUENCER_CNAME_TARGETS) + \
        COMMON_PLATFORMS + tuple(p for p, _, _ in ABUSED_HOSTING)
    def _base(h):  # approximate registrable domain (last two labels)
        return ".".join(h.split(".")[-2:])
    result["other_link_domains"] = []
    for h in result["link_hosts"]:
        b = _base(h)
        if b != _base(from_domain or "x.invalid") and not any(m in h for m in platform_markers) \
                and b not in result["other_link_domains"]:
            result["other_link_domains"].append(b)

    # Company identification with confidence scoring
    result["company_id"] = identify_company(result)

    return result


def identify_company(info: dict) -> dict:
    """
    Attempt to identify the company behind the spam. Returns:
    - company_domain: the likely company domain
    - signals: list of evidence supporting the identification
    - confidence: HIGH / MEDIUM / LOW / UNKNOWN
    - notes: explanation for human review
    """
    signals = []
    domains_seen = {}  # domain → list of signal descriptions

    # Signal 1: From domain (strongest if it's a company domain, not a freemail)
    from_domain = ""
    from_match = re.search(r'@([\w.-]+)', info.get("from", ""))
    if from_match:
        from_domain = from_match.group(1).lower()
        freemail = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
                    "aol.com", "protonmail.com", "icloud.com", "mail.com"}
        if info.get("forged_from"):
            signals.append(f"From domain {from_domain} is forged (non-existent TLD) — ignored")
        elif from_domain not in freemail:
            signals.append(f"From address uses company domain: {from_domain}")
            domains_seen.setdefault(from_domain, []).append("From header")

    # Signal 2: Return-Path domain (often reveals the real sender)
    rp_match = re.search(r'@([\w.-]+)', info.get("return_path", ""))
    if rp_match:
        rp_domain = rp_match.group(1).lower()
        # Strip ESP subdomains (em1234.company.com → company.com)
        rp_base = re.sub(r'^em\d+\.', '', rp_domain)
        rp_base = re.sub(r'^bounces?\+?\w*\.', '', rp_base)
        if rp_base and rp_base != from_domain:
            signals.append(f"Return-Path domain: {rp_domain} (base: {rp_base})")
            domains_seen.setdefault(rp_base, []).append("Return-Path")
        elif rp_base:
            signals.append(f"Return-Path confirms From domain: {rp_base}")
            domains_seen.setdefault(rp_base, []).append("Return-Path (confirms)")

    # Signal 3: DKIM signing domain
    for d in info.get("dkim_domains", []):
        d = d.lower()
        # Skip ESP signing domains
        esp_domains = {"sendgrid.net", "mailgun.org", "amazonses.com",
                       "postmarkapp.com", "mandrillapp.com"}
        esp_suffixes = (".aliyuncs.com", ".263.net", ".mcsv.net", ".hubspotemail.net",
                        ".sparkpostmail.com", ".onmicrosoft.com", "gappssmtp.com")
        if d not in esp_domains and not d.endswith(esp_suffixes):
            signals.append(f"DKIM signed by company domain: {d}")
            domains_seen.setdefault(d, []).append("DKIM signature")

    # Signal 4: List-Unsubscribe domain
    unsub = info.get("list_unsubscribe", "")
    unsub_match = re.search(r'https?://([\w.-]+)', unsub)
    if unsub_match:
        unsub_domain = unsub_match.group(1).lower()
        # Strip common prefixes
        unsub_base = re.sub(r'^(email|mail|unsubscribe|links?|click|track)\.',
                            '', unsub_domain)
        if unsub_base.endswith(".aliyuncs.com") or (
                info.get("forged_from") and unsub_base.rsplit(".", 1)[-1] == from_domain.rsplit(".", 1)[-1]):
            unsub_base = ""  # platform-hosted or same fake TLD — not a company signal
        if unsub_base:
            signals.append(f"Unsubscribe link domain: {unsub_domain}")
            domains_seen.setdefault(unsub_base, []).append("List-Unsubscribe")

    # Signal 4b: Reply-To domain (where replies go — often the operation's persistent inbox)
    rt_match = re.search(r'@([\w.-]+)', info.get("reply_to", "") or "")
    if rt_match:
        rt_domain = rt_match.group(1).lower()
        _base2 = lambda d: ".".join(d.split(".")[-2:])
        if _base2(rt_domain) == _base2(from_domain):
            pass
        elif rt_domain not in {"gmail.com", "qq.com", "163.com", "outlook.com",
                                                           "hotmail.com", "yahoo.com", "126.com"}:
            signals.append(f"Reply-To uses a different domain: {rt_domain}")
            domains_seen.setdefault(rt_domain, []).append("Reply-To")
        else:
            signals.append(f"Reply-To is a freemail inbox ({rt_domain}) — report the address to that provider")

    # Signal 5: Body mentions (company name, product, website)
    body = info.get("body_snippet", "")
    body_urls = re.findall(r'https?://([\w.-]+)', body)
    for url_domain in body_urls:
        url_base = re.sub(r'^(www|app|links?|click|track|email)\.', '',
                          url_domain.lower())
        # Skip known ESP/tracking domains
        skip = {"sendgrid.net", "mailgun.org", "google.com", "bit.ly",
                "mailchi.mp", "hubspot.com", "salesforce.com"}
        if url_base not in skip and not url_base.startswith("127.") \
                and not any(url_base.endswith(c) for c in COMMON_PLATFORMS) \
                and not any(p.strip(".") in url_base for p, _, _ in ABUSED_HOSTING):
            signals.append(f"Body contains URL: {url_domain}")
            domains_seen.setdefault(url_base, []).append("Body URL")

    # Score confidence
    if not domains_seen:
        return {
            "company_domain": None,
            "signals": signals,
            "confidence": "UNKNOWN",
            "notes": "Could not identify the sender company. The spam may use "
                     "anonymized infrastructure. Manual investigation required."
        }

    # Find the most corroborated domain
    best_domain = max(domains_seen.keys(),
                      key=lambda d: len(domains_seen[d]))
    signal_count = len(domains_seen[best_domain])
    sources = domains_seen[best_domain]

    if signal_count >= 3:
        confidence = "HIGH"
        notes = (f"Domain '{best_domain}' confirmed by {signal_count} independent "
                 f"signals ({', '.join(sources)}). Very likely the correct company.")
    elif signal_count == 2:
        confidence = "MEDIUM"
        notes = (f"Domain '{best_domain}' supported by {signal_count} signals "
                 f"({', '.join(sources)}). Likely correct but verify before filing "
                 f"regulatory complaints.")
    else:
        # Check if From domain is a real company domain (not freemail)
        if "From header" in sources:
            confidence = "MEDIUM"
            notes = (f"Domain '{best_domain}' appears in From header only. "
                     f"Could be the company or a proxy domain. Check the website "
                     f"at https://{best_domain} to confirm.")
        else:
            confidence = "LOW"
            notes = (f"Domain '{best_domain}' found in {sources[0]} only. "
                     f"The actual company may be different — spammers sometimes "
                     f"use proxy domains or third-party senders. Manual investigation "
                     f"strongly recommended before filing reports.")

    # Check for domain mismatch (potential obfuscation)
    unique_bases = set(domains_seen.keys())
    if len(unique_bases) > 2:
        notes += (f"\n⚠️  Multiple distinct domains detected ({', '.join(unique_bases)}). "
                  f"This may indicate the sender is obscuring their identity or using "
                  f"third-party infrastructure. Investigate each domain.")

    return {
        "company_domain": best_domain,
        "all_domains": dict(domains_seen),
        "signals": signals,
        "confidence": confidence,
        "notes": notes,
    }


def format_report(info: dict) -> str:
    """Format parsed header info as a readable report."""
    lines = []
    lines.append("=" * 50)
    lines.append("  EMAIL HEADER ANALYSIS")
    lines.append("=" * 50)
    lines.append("")

    lines.append(f"From: {info['from']}")
    lines.append(f"Subject: {info.get('subject', '[none]')}")
    lines.append(f"Reply-To: {info['reply_to'] or '[not set]'}")
    lines.append(f"Return-Path: {info['return_path'] or '[not set]'}")
    lines.append(f"Message-ID: {info['message_id']}")
    lines.append(f"List-Unsubscribe: {info['list_unsubscribe'] or '[not set]'}")
    lines.append("")

    # Company Identification section
    cid = info.get("company_id", {})
    if cid:
        lines.append("## COMPANY IDENTIFICATION")
        if cid.get("company_domain"):
            lines.append(f"  Domain: {cid['company_domain']}")
        lines.append(f"  Confidence: {cid.get('confidence', 'UNKNOWN')}")
        lines.append(f"  Notes: {cid.get('notes', '')}")
        if cid.get("signals"):
            lines.append("  Signals:")
            for s in cid["signals"]:
                lines.append(f"    • {s}")
        if cid.get("all_domains") and len(cid["all_domains"]) > 1:
            lines.append("  All domains found:")
            for d, sources in cid["all_domains"].items():
                lines.append(f"    {d} ← {', '.join(sources)}")
        lines.append("")

    lines.append("## Authentication")
    lines.append(f"  SPF: {info['spf_result'] or '[not checked]'}")
    lines.append(f"  DKIM: {info['dkim_result'] or '[not checked]'}")
    lines.append(f"  DMARC: {info['dmarc_result'] or '[not checked]'}")
    lines.append("")

    if info["dkim_domains"]:
        lines.append("## DKIM Signing Domains")
        for d in info["dkim_domains"]:
            lines.append(f"  - {d}")
        lines.append("")

    if info["sending_ips"]:
        lines.append("## Sending IPs (public)")
        for ip in info["sending_ips"]:
            lines.append(f"  - {ip}")
        lines.append("")

    if info["esps_detected"]:
        lines.append("## DETECTED ESPs")
        for esp in info["esps_detected"]:
            lines.append(f"  ✓ {esp['name']}")
            lines.append(f"    Abuse: {esp['abuse_contact']}")
            lines.append(f"    Matched: {esp['matched_on']}")
        lines.append("")

    if info.get("flags"):
        lines.append("## ⚠️  FLAGS")
        for f in info["flags"]:
            lines.append(f"  - {f}")
        lines.append("")

    if info.get("abuse_headers") or info.get("abuse_links"):
        lines.append("## ★ PLATFORM-PROVIDED ABUSE CHANNELS (official, account-specific — report here first)")
        for k, v in info.get("abuse_headers", []):
            lines.append(f"  {k}: {v}")
        for u in info.get("abuse_links", []):
            lines.append(f"  link: {u}")
        lines.append("  The sending platform put these in the message for exactly this purpose. Feedback-ID /")
        lines.append("  X-AntiAbuse values identify the exact sending account or server — quote them in every report.")
        lines.append("")

    th = info.get("trusted_hop") or {}
    if th:
        lines.append("## VERIFIED SENDING SERVER (trust boundary: recorded by your own mail server)")
        lines.append(f"  {th['rdns']} [{th['ip']}]  (HELO: {th['helo']}, received by {th['by']})")
        if th.get("provider"):
            lines.append(f"  ✓ Sending service: {th['provider']}")
        if th.get("mismatch"):
            lines.append("  ⚠️  HELO name doesn't match reverse DNS — the sender lied about its hostname")
        lines.append("  Received lines BELOW this hop are written by the sender and can be forged.")
        lines.append(f"  IP owner/abuse: `whois {th['ip']}` (report there unless it's a big shared provider "
                     f"like Google/Microsoft — then use the provider channel)")
        lines.append("")

    _b = lambda d: ".".join((d or "").split(".")[-2:])
    if info.get("reply_to_domain") and _b(info.get("reply_to_domain")) != _b(info.get("from_domain")):
        lines.append("## REPLY-TO DIFFERS FROM SENDER")
        lines.append(f"  Replies go to: {info['reply_to']}")
        lines.append("  Rotating sending domains + a stable Reply-To = the Reply-To inbox/domain is the operation's")
        lines.append("  persistent asset. Run recon.sh on it, include it in blocklist reports, and if it's a")
        lines.append("  freemail/hosted inbox (qq.com, gmail.com, …), report the address to that provider.")
        _rtd = info.get("reply_to_domain", "")
        if _rtd in FREEMAIL_ABUSE:
            lines.append(f"  ✓ Freemail inbox → report the address to: {FREEMAIL_ABUSE[_rtd]}")
        lines.append("")

    if info.get("abused_hosting"):
        lines.append("## PAYLOAD HOSTED ON A LEGIT PLATFORM (report the exact URL; not the brand domain)")
        for h in info["abused_hosting"]:
            lines.append(f"  - {h['platform']}: {h['url']}")
            lines.append(f"    Report: {h['report']}")
        lines.append("")

    mp = info.get("mailbox_provider") or {}
    if mp:
        lines.append("## MAILBOX PROVIDER (sending side)")
        lines.append(f"  ✓ {mp['provider']}")
        lines.append(f"    Report to: {mp['abuse']}")
        lines.append("")

    if info.get("sequencers"):
        lines.append("## SENDING PLATFORM FROM TRACKING LINKS")
        for s in info["sequencers"]:
            label = s["name"] or "[unrecognised]"
            lines.append(f"  ✓ {label}  ({s['host']}, {s['via']})")
            lines.append(f"    Abuse: {s['abuse']}")
        lines.append("")

    if info.get("link_hosts"):
        lines.append("## LINK HOSTS IN BODY (candidates for SURBL/URIBL/Spamhaus DBL; brand domain is usually here)")
        for h in info["link_hosts"]:
            lines.append(f"  - {h}")
        if info.get("other_link_domains"):
            lines.append(f"  Sending domain: {info.get('from_domain') or '[unknown]'}. Linked domains that differ "
                         f"(likely the BRAND domain if the sender is a lookalike): "
                         f"{', '.join(info['other_link_domains'])}")
            lines.append("  → Run recon.sh on both; report the brand domain to the blocklists too.")
        lines.append("")

    if info["x_headers"]:
        lines.append("## X-Headers (notable)")
        for k, v in info["x_headers"].items():
            # Only show interesting ones
            if any(kw in k.lower() for kw in ["mailer", "campaign", "sg", "pm", "mc", "ses", "mailgun", "provider"]):
                lines.append(f"  {k}: {v}")
        lines.append("")

    if info["received_chain"]:
        lines.append(f"## Received Chain ({len(info['received_chain'])} hops)")
        for i, r in enumerate(info["received_chain"]):
            lines.append(f"  [{i}] {r[:200]}{'...' if len(r) > 200 else ''}")
        lines.append("")

    lines.append("=" * 50)
    return "\n".join(lines)


def email_link(info: dict, gmail_id: str = "", account: str = "0") -> str:
    """Link the user can click to open the original. Gmail API id if known; otherwise a
    Gmail search on the Message-ID (works for any Gmail account, incl. Spam)."""
    if gmail_id:
        return f"https://mail.google.com/mail/u/{account}/#all/{gmail_id}"
    mid = (info.get("message_id") or "").strip().strip("<>")
    if not mid:
        return ""
    from urllib.parse import quote
    return f"https://mail.google.com/mail/u/{account}/#search/{quote('in:anywhere rfc822msgid:' + mid)}"


def format_card(info: dict, n: int = 1, link: str = "") -> str:
    """Compact review card for manual (review) mode: one per email, for the user to approve or skip."""
    L = []
    frm = info.get("from") or "[no From]"
    L.append(f"### [{n}] {info.get('subject') or '[no subject]'}")
    L.append(f"**From:** {frm}" + (f"  ·  [open email]({link})" if link else ""))
    if info.get("intro"):
        L.append(f"> {info['intro'][:220]}…")
    found = []
    for k, v in info.get("abuse_headers", [])[:2]:
        found.append(f"★ platform abuse channel — `{k}: {v[:110]}`")
    seq_names = {sq["name"].split(" (")[0] for sq in info.get("sequencers", []) if sq.get("name")}
    for sq in info.get("sequencers", [])[:2]:
        if sq.get("name"):
            found.append(f"sending platform: {sq['name']} (tracking host {sq['host']}) → {sq['abuse']}")
    for e in info.get("esps_detected", [])[:2]:
        if e["name"].split(" (")[0] not in seq_names:
            found.append(f"sending platform: {e['name']} → {e['abuse_contact']}")
    mp = info.get("mailbox_provider") or {}
    if mp:
        found.append(f"mailboxes: {mp['provider']} → {mp['abuse'].split(' (')[0]}")
    th = info.get("trusted_hop") or {}
    if th:
        shared = th.get("provider") is not None
        found.append(f"sending server: {th['rdns']} [{th['ip']}]" +
                     (f" — {th['provider']} shared infrastructure, report via the platform above" if shared
                      else " → IP owner's abuse contact (`whois` / recon.sh)"))
    if info.get("reply_to_domain") and ".".join(info["reply_to_domain"].split(".")[-2:]) != \
            ".".join((info.get("from_domain") or "").split(".")[-2:]):
        ch = FREEMAIL_ABUSE.get(info["reply_to_domain"], "registrar + blocklists (run recon.sh)")
        found.append(f"reply-to (persistent inbox): {info['reply_to']} → {ch}")
    if info.get("other_link_domains"):
        found.append(f"brand/link domain(s): {', '.join(info['other_link_domains'][:3])} → blocklists + registrar")
    _seen_pl = set()
    for h in info.get("abused_hosting", []):
        if h["platform"] in _seen_pl:
            continue
        _seen_pl.add(h["platform"])
        found.append(f"hosted payload: {h['platform']} ({h['url'][:70]}…) → {h['report']}")
    if found:
        L.append("**Supply chain found:**")
        L.extend(f"- {x}" for x in found)
    for f in info.get("flags", []):
        L.append(f"- ⚠️ {f}")
    cid = info.get("company_id") or {}
    L.append(f"**Sender confidence:** {cid.get('confidence', 'UNKNOWN')} ({cid.get('company_domain') or 'unknown'})")
    L.append("**Decision:** ☐ report  ☐ skip  ☐ unsubscribe instead (I signed up)")
    return "\n".join(L)


if __name__ == "__main__":
    argv = sys.argv[1:]
    use_dns = "--no-dns" not in argv
    card = "--card" in argv
    gmail_id = argv[argv.index("--gmail-id") + 1] if "--gmail-id" in argv else ""
    args = [a for i, a in enumerate(argv) if a not in ("--no-dns", "--card", "--gmail-id")
            and not (i > 0 and argv[i - 1] == "--gmail-id")]
    if len(args) < 1:
        print("Usage: parse-headers.py [--no-dns] [--card [--gmail-id ID]] <message.eml>")
        print("       cat message.eml | parse-headers.py [--no-dns] -")
        print("  --card        compact review card (manual/review mode) instead of the full report")
        print("  --gmail-id    Gmail API message id, for a direct 'open email' link")
        sys.exit(1)

    source = args[0]
    if source == "-":
        raw = sys.stdin.read()
    else:
        with open(source, "r") as f:
            raw = f.read()

    info = parse_headers(raw, use_dns=use_dns)
    if card:
        print(format_card(info, link=email_link(info, gmail_id)))
    else:
        print(format_report(info))
