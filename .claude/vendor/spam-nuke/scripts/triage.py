#!/usr/bin/env python3
"""
triage.py — Rank a batch of spam emails by how likely they are to be genuine spam, and
print the "a bit careful" review: numbered one-line blurbs, most-likely-spam first, in
batches (10 by default), with report-by-default wording.

Usage:
  triage.py [--prior prior.json] [--ids ids.json] [--batch 10] [--page 1] [--no-dns] msg1.eml msg2.eml ...

  --prior  JSON {"<sending domain or address>": <count of non-spam emails exchanged>}.
           The agent builds this with its mail tool (search outside Spam for mail from the
           sender's domain, and Sent for mail to it). Any count > 0 → "probably subscribed".
  --ids    JSON {"<eml filename>": "<Gmail message id>"} for direct "open" links
           (otherwise a Gmail Message-ID search link is used).
  --page   Which batch to print (1 = highest-scoring 10).

Scores are heuristic (0–100) and come with their reasons; they decide ORDER and the
default, never whether the ground rules apply. Python 3 standard library only.
"""
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("parse_headers", os.path.join(HERE, "parse-headers.py"))
ph = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ph)  # type: ignore[union-attr]

ACADEMIC = re.compile(r"call for (papers|manuscripts|abstracts)|submit (your )?(paper|article|manuscript|abstract|speech)"
                      r"|speaker|keynote|editorial office|journal|conference|volume \d+|issue \d+|peer[- ]review"
                      r"|scopus|indexed|chair/|invited? to (speak|submit)|dear dr\.?", re.I)
SCAM = re.compile(r"collaboration request|peace be with you|beneficiar|inheritance|next of kin|compensation fund"
                  r"|fund transfer|barrister|director[- ]general|consignment|lottery|you (have )?won|wire transfer"
                  r"|crypto ?currency investment|god bless", re.I)
PHISH = re.compile(r"storage .{0,20}(full|100%)|payment (failed|method)|verify your (account|identity)"
                   r"|password (expir|reset)|account (suspend|locked|deactivat)|unusual sign-?in", re.I)
NEWSLETTER = re.compile(r"newsletter|\d+% off|\$\d+ off|\bsale\b|shop now|deals?\b|win .{0,30}tickets"
                        r"|new arrivals|wardrobe|members? (only|exclusive)|private access", re.I)
FREEMAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "qq.com",
            "163.com", "126.com", "tutamail.com", "tutanota.com", "tuta.io", "proton.me", "protonmail.com"}


SEQUENCERS = ("Instantly", "Smartlead", "lemlist", "Lemlist", "Apollo", "Outreach", "Salesloft", "Reply.io",
              "Woodpecker", "Mailshake", "Mixmax")
NEWSLETTER_ESPS = ("Mailchimp", "SendGrid", "AWS SES", "Amazon SES", "Mailgun", "HubSpot", "Salesforce", "Klaviyo",
                   "Brevo", "Constant Contact", "ActiveCampaign", "Customer.io", "Postmark", "SparkPost")


def base(d):
    parts = (d or "").lower().strip(".").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("com", "co", "org", "net", "ac", "edu", "gov", "my"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def score(info):
    """Return (score 0-100, reasons, category)."""
    s, why = 30, []
    text = f"{info.get('subject', '')} {info.get('intro', '')}"
    flags = info.get("flags", [])
    if any("impersonates" in f for f in flags):
        s += 30; why.append("display name impersonates you")
    if any("does not exist" in f for f in flags):
        s += 30; why.append("forged sender domain")
    if (info.get("trusted_hop") or {}).get("mismatch"):
        s += 10; why.append("sending server lies about its hostname")
    rtd = info.get("reply_to_domain") or ""
    if rtd and base(rtd) != base(info.get("from_domain") or ""):
        s += 20; why.append(f"replies go to {'a freemail inbox' if rtd in FREEMAIL else 'a different domain'} ({rtd})")
    xanti = any(k.lower() == "x-antiabuse" for k, _ in info.get("abuse_headers", []))
    if xanti and rtd in FREEMAIL:
        s += 20; why.append("sent from a hacked shared-hosting account")
    if not info.get("list_unsubscribe"):
        s += 10; why.append("no unsubscribe header")
    if SCAM.search(text):
        s += 30; why.append("advance-fee scam wording")
    if PHISH.search(text):
        s += 15; why.append("credential/payment lure")
    if ACADEMIC.search(text):
        s += 20; why.append("predatory journal/conference pattern")
    plat = " ".join([sq.get("name") or "" for sq in info.get("sequencers", [])] +
                    [e["name"] for e in info.get("esps_detected", [])])
    cold_tool = any(n in plat for n in SEQUENCERS)
    if cold_tool:
        s += 10; why.append("cold-email sequencer")
    elif any(n in plat for n in NEWSLETTER_ESPS) and info.get("list_unsubscribe") \
            and not (rtd and base(rtd) != base(info.get("from_domain") or "")) \
            and not (SCAM.search(text) or PHISH.search(text) or ACADEMIC.search(text)):
        s -= 15; why.append("looks like a compliant newsletter (bulk ESP + unsubscribe)")
    fd = info.get("from_domain") or ""
    if fd in FREEMAIL and not (SCAM.search(text) or PHISH.search(text) or ACADEMIC.search(text)):
        s -= 15; why.append("individual personal account, one-off")
    if (info.get("company_id") or {}).get("confidence") in ("LOW", "UNKNOWN"):
        s += 5; why.append("sender identity obscured")
    if NEWSLETTER.search(text):
        s -= 20; why.append("newsletter/retail wording")
    s = max(0, min(100, s))

    if any("impersonates" in f or "does not exist" in f for f in flags) or PHISH.search(text) and flags:
        cat = "Phishing"
    elif xanti and rtd in FREEMAIL or SCAM.search(text):
        cat = "Scam (hacked sender)" if xanti else "Scam"
    elif ACADEMIC.search(text):
        cat = "Predatory journal/conference"
    elif cold_tool or info.get("mailbox_provider") or (rtd and base(rtd) != base(info.get("from_domain") or "")):
        cat = "Cold outreach"
    else:
        cat = "Bulk marketing"
    return s, why, cat


def channels(info):
    out = []
    for k, v in info.get("abuse_headers", []):
        if k.lower() in ("x-mail-abuse-inquiries", "x-report-abuse"):
            plat = "Instantly" if "instantly" in v else ("Mailchimp" if "mailchimp" in v else k)
            out.append(f"{plat} (per-message abuse link)")
        elif k.lower() == "x-antiabuse" and "Primary Hostname" in v:
            out.append(f"host {v.split('-', 1)[-1].strip()} (hacked account)")
    names = {o.split(" (")[0] for o in out}
    for sq in info.get("sequencers", []):
        if sq.get("name") and sq["name"].split(" (")[0] not in names:
            out.append(sq["name"].split(" (")[0]); names.add(sq["name"].split(" (")[0])
    for e in info.get("esps_detected", []):
        n = e["name"].split(" (")[0]
        if n not in names:
            out.append(n); names.add(n)
    mp = info.get("mailbox_provider") or {}
    if mp:
        out.append("Google Workspace" if "Workspace" in mp["provider"] else mp["provider"].split(" (")[0])
    th = info.get("trusted_hop") or {}
    if th and not th.get("provider") and not any("host " in o for o in out):
        out.append(f"server owner of {th['ip']}")
    rtd = info.get("reply_to_domain") or ""
    if rtd and base(rtd) != base(info.get("from_domain") or ""):
        out.append(f"reply inbox ({rtd})")
    for h in info.get("abused_hosting", [])[:1]:
        out.append(h["platform"])
    out.append("blocklists")
    return list(dict.fromkeys(out))


def main():
    argv = sys.argv[1:]
    opt = lambda k, d=None: argv[argv.index(k) + 1] if k in argv else d
    prior = json.load(open(opt("--prior"))) if opt("--prior") else {}
    gids = json.load(open(opt("--ids"))) if opt("--ids") else {}
    batch, page = int(opt("--batch", 10)), int(opt("--page", 1))
    use_dns = "--no-dns" not in argv
    skip_next = {"--prior", "--ids", "--batch", "--page"}
    files = [a for i, a in enumerate(argv) if not a.startswith("--") and not (i and argv[i - 1] in skip_next)]
    if not files:
        print(__doc__); sys.exit(1)

    items = []
    for f in files:
        raw = open(f, "rb").read().decode("utf-8", errors="replace")
        info = ph.parse_headers(raw, use_dns=use_dns)
        fd = info.get("from_domain") or ""
        addr = re.search(r"[\w.+-]+@[\w.-]+", info.get("from") or "")
        key_addr = addr.group(0).lower() if addr else ""
        p = prior.get(key_addr, 0) if fd in FREEMAIL else prior.get(base(fd), prior.get(fd, 0))
        sc, why, cat = score(info)
        link = ph.email_link(info, gids.get(os.path.basename(f), ""))
        items.append({"info": info, "score": sc, "why": why, "cat": cat, "prior": p, "link": link})

    report = sorted([x for x in items if not x["prior"] and x["score"] >= 40], key=lambda x: -x["score"])
    unsure = sorted([x for x in items if not x["prior"] and x["score"] < 40], key=lambda x: -x["score"])
    subscribed = [x for x in items if x["prior"]]

    pages = max(1, -(-len(report) // batch))
    chunk = report[(page - 1) * batch: page * batch]
    first = (page - 1) * batch + 1
    print("> ⚠️ Every report goes out in your name to real abuse teams. Reporting mail you actually signed up for, or a "
          "real contact, is a false positive: it wastes their time, weakens genuine reports, and can hurt a "
          "legitimate sender. If unsure, skip it or unsubscribe instead.\n")
    print(f"**Batch {page}/{pages}: {len(chunk)} of {len(report)} likely spam, most certain first.** "
          f"(Not counted: {len(subscribed)} you've had mail with, {len(unsure)} unsure — listed at the end.)\n")
    for n, x in enumerate(chunk, first):
        inf = x["info"]
        sender = re.sub(r"\s*<.*", "", inf.get("from") or "").strip('" ') or "?"
        dom = inf.get("from_domain") or "?"
        subj = (inf.get("subject") or "[no subject]")[:60]
        reasons = "; ".join(x["why"][:3])
        ch = channels(inf)
        ch_txt = ", ".join(ch[:4]) + (f" +{len(ch) - 4}" if len(ch) > 4 else "")
        link = f" · [open]({x['link']})" if x["link"] else ""
        print(f"**{n}. {x['cat']}** ({x['score']}) · {sender} ({dom}) · *{subj}*{link}")
        print(f"   {reasons}. → {ch_txt}")
    print(f"\n**I'll report all {len(chunk)} unless you say otherwise:** reply `skip 3 7`, `unsub 5` (you signed up), "
          f"`details 2` (full card), or `stop`. Anything else, e.g. `go`, means report the rest"
          + (" and show the next batch." if page < pages else "."))
    if page == pages and (unsure or subscribed):
        print("\n**Not reporting by default:**")
        for x in unsure:
            inf = x["info"]
            print(f"- unsure ({x['score']}) · {re.sub(r'<.*', '', inf.get('from') or '').strip()} · "
                  f"*{(inf.get('subject') or '')[:50]}* — {'; '.join(x['why'][:2]) or 'no strong spam signals'}"
                  + (f" · [open]({x['link']})" if x["link"] else ""))
        for x in subscribed:
            inf = x["info"]
            print(f"- you've had mail with them ({x['prior']}+) · {re.sub(r'<.*', '', inf.get('from') or '').strip()} · "
                  f"*{(inf.get('subject') or '')[:50]}* — `unsub` instead?" + (f" · [open]({x['link']})" if x["link"] else ""))
        print("Say `report N` to move one up, or `unsub N` to unsubscribe.")


if __name__ == "__main__":
    main()
