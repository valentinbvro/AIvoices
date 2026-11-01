# spam-nuke

An agent skill that maps a spammer's entire supply chain (mailboxes, sending platform, domains, lead vendor, voice carrier, regulators) and reports them to every layer of it. **Every channel it uses is an official one:** abuse desks, blocklists, carrier traceback and regulators that exist specifically to receive these reports. No hacking, no harassment, no gray areas.

## Why: a dark forest for spammers

Spam runs on an asymmetry. Sending is nearly free, and fighting back costs the recipient an hour of header-reading, WHOIS lookups and web forms. So almost nobody fights back, and the expected cost of hitting any one inbox is roughly zero.

Agents remove the recipient's cost. With this skill, "nuke this spammer" takes one sentence. Spammers can't tell which inboxes have an agent behind them, so every message they send becomes a lottery ticket for an expensive event:

- a suspended Google Workspace tenant and weeks of mailbox warmup lost
- a terminated sending-platform account
- their **brand** domain on Spamhaus, which hurts all their mail, invoices included
- a traceback that gets their voice carrier cut off from the US phone network
- a regulator file with their name on it, or statutory damages per message

```
expected cost per message = P(recipient is armed) × cost of a full-stack response
```

Agents raise P. Hitting the whole supply chain, instead of one throwaway address, raises the cost. Past a certain point the rational move for senders is the one from Liu Cixin's *Dark Forest*: don't reveal yourself. In practice that means only emailing or calling people who opted in.

This works because the systems already exist. Abuse desks, Spamhaus, the FCC's traceback machinery and the FTC's complaint database all have thresholds and penalties built in. What they've been short of is input. It also only works if reports are **accurate**, which is why the skill is strict about evidence (see below).

The full layer-by-layer reasoning, with sources, is in [`references/supply-chain.md`](references/supply-chain.md).

## The supply chain it hits

| Layer | Official channel | What a report costs the sender |
|---|---|---|
| Lead vendor that sold your address | GDPR/CCPA deletion, California DROP | You disappear from every future buyer's list |
| Lookalike sending domains | Registrar abuse, Spamhaus DBL / SURBL / URIBL | Weeks of warmup wasted per burned domain |
| Google Workspace / M365 mailboxes | `abuse@<domain>` (Google monitors it), "Report spam" | Seat or whole-tenant suspension |
| Sequencer / ESP (Instantly, Smartlead, SendGrid…) | Platform abuse desk | Account termination; their rules are stricter than the law |
| Brand domain (in links and signature) | Domain blocklists | Months of reputation; affects all their mail |
| Robocall voice carrier | FTC/FCC complaints → Industry Traceback Group | Removal from the FCC Robocall Mitigation Database: every US carrier must refuse its traffic |
| Caller-ID numbers | DoNotCall.gov reports (shared daily with carriers) | "Spam Likely" labels; answer rate collapses |
| Texting platform (Twilio, Bandwidth…) | Platform abuse, 7726 | Campaign or number suspension |
| The company | FTC, FCC, state AGs, EU DPAs, ICO, CASL, ACMA, PDPC | Aggregated into enforcement; per-message penalties |

It covers **email** (cold outreach, spam, phishing), **calls** (robocalls, voicemail) and **texts**, with channels for the US, EU, UK, Canada, Australia and Singapore.

## Works with any agent, any tools

Any agent that can read a `SKILL.md` can use it, and it doesn't assume particular tools. The agent uses whatever it has: mail access to pull raw messages and send abuse reports, a browser for government web forms, a shell for DNS/WHOIS, and phone or messaging access for call logs and texts. If it can't reach a channel, it writes the filled-in draft and adds it to your checklist.

```bash
# Claude Code
git clone https://github.com/menhguin/spam-nuke ~/.claude/skills/spam-nuke

# Hermes
git clone https://github.com/menhguin/spam-nuke ~/.hermes/skills/spam-nuke
```

For any other agent, put the folder where it loads skills from, or give it the link and say "read SKILL.md and follow it". Then say *"nuke this spammer"*, *"do something about the spam calls in my voicemail"*, or *"report this phishing text"*.

## Guardrails (precision is the weapon)

- **Checks you didn't sign up.** The agent searches your inbox for prior contact first and unsubscribes instead if you opted in. False positives are what teach abuse desks to ignore reports.
- **Claims only what the evidence shows, under the law that applies.** Example: in the US, unsolicited email isn't illegal by itself (CAN-SPAM is an opt-out law), so the agent cites real violations, or platform-policy breaches, rather than inventing them.
- **One report per channel per incident,** tracked in a ledger. Repeat offenders get escalated, not re-spammed with reports.
- **Never engages with scams:** no replies, link clicks or callbacks. With real, identifiable companies it may send one official opt-out, because mail after that is a clean violation.
- **Discloses that an agent prepared each report,** with your real contact details.
- **Three modes, from careful to sicko.** *Really careful:* you approve every outgoing report, word for word. *A bit careful* (default): spam in batches of 10, most certain first, one line each (category, why, a link to the original, where it'll be reported). It reports them unless you reply `skip 3 7` / `unsub 5` / `stop`. On the first run it simply asks which mode you want. *Sicko mode:* you pre-authorize, and it sweeps the whole Spam folder (and new spam as it arrives), files every channel including regulators, escalates repeat offenders, caps outbound reports to protect your own mailbox, and sends you a digest. All three keep the same floor: no reports against anyone you have a relationship with, evidence-only claims, and no lawsuits filed. A trust ladder suggests moving up a level after clean runs and drops a level after any false positive.

## Contents

| Path | What |
|---|---|
| `SKILL.md` | The agent's workflow: dark-forest rationale, supply-chain map, ground rules, triage, then the email, calls and texts workflows and the ledger |
| `references/supply-chain.md` | Each layer in depth: what it is, its official channel, what a report does, what it costs the sender, and where reports don't bite |
| `references/report-targets.md` | Abuse contacts, blocklists, regulators by country, and sequencer tracking fingerprints |
| `references/report-formats.md` | Templates: platform, mailbox provider, registrar, host, FTC, GDPR, opt-out, data deletion, phone complaints |
| `scripts/parse-headers.py` | Email analysis: verified sending server (forged-header boundary), mailbox provider (Workspace/M365), ESP and sequencer fingerprints, Reply-To mismatch (the operation's persistent inbox), brand vs sending domain, payloads on abused platforms, phishing flags. Python 3 standard library |
| `scripts/recon.sh` | DNS/WHOIS map: registrar and abuse contact, domain age, MX provider, host, SPF platforms, DKIM, blocklist status. Needs `dig` and `whois` |
| `scripts/triage.py` | "A bit careful" batch view: ranks emails by spam likelihood (with reasons), 10 per batch, one-line blurbs with open links, report-by-default wording, plus an unsure / probably-subscribed list |
| `scripts/check-lists.sh` | Read-only blocklist status for domains and IPs (Spamhaus DBL/ZEN, SURBL, URIBL, SpamCop): before filing, and two weeks after as a success check |

Abuse addresses and form URLs move, so the agent confirms each one before sending. PRs with updated contacts or new sequencer fingerprints are welcome.

MIT licensed.
