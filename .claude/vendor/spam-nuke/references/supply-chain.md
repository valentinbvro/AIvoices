# The spam supply chain, layer by layer

What a spam operation actually runs on, which official channel reaches each layer, what a report there does, and what it costs the sender. Use this to decide where reports go and in what order, and to tell the user honestly what to expect.

## The principle: hit what's expensive to replace

Spam is a business. It continues because the expected cost of each message is lower than the revenue it brings in. Most anti-spam effort works on one link (filtering, URL blocklisting, site takedown), and spammers route around single links cheaply. The study that mapped the whole chain end to end (Levchenko et al., ["Click Trajectories: End-to-End Analysis of the Spam Value Chain"](https://www.ieee-security.org/TC/SP2011/PAPERS/2011/paper027.pdf), IEEE S&P 2011) found the decisive variable was **replacement cost**. Hosting was abundant and cheap to switch. Domains cost "under $1 in bulk" and registrars were easy to swap. Payment was the chokepoint: just three banks serviced over 95% of the spam-advertised goods they bought, and a new merchant account takes due diligence, fees and time.

The same logic holds for modern cold outreach and robocalls. So for each layer below, ask: **how long, and how much money, does it take them to rebuild what this report damages?** Report to every layer, but count success at the expensive layers.

Rough replacement-cost ranking for a typical cold-email operation, from cheapest to most expensive:

| Layer | Replacement cost for the sender |
|---|---|
| A single sending address | Minutes |
| A lookalike sending domain | ~$10 plus DNS setup, but **weeks** of warmup before it delivers well |
| Warmed mailboxes (Workspace/M365 seats) | Seat fees plus **2–4+ weeks** of warmup each |
| Sequencer / email-platform account | Lost campaigns, lists, sequences, prepaid plan; KYC to get a new one; a ban can follow the company |
| Primary brand domain reputation | **Months**, and it also hurts their transactional mail, invoices and customer replies |
| Regulatory / legal exposure | Open-ended: per-message penalties, statutory damages, investigations |

Robocall operations follow the same pattern. Caller-ID numbers are cheap and burned constantly. The originating carrier's access to the US phone network is the expensive part, because once it's revoked, every other carrier must refuse its traffic.

## Why this creates a dark forest for spammers

Spam wins on an asymmetry: **sending is nearly free and complaining is expensive.** A cold emailer can reach 10,000 inboxes for the price of a few mailbox seats. A recipient who wants to fight back faces an hour of header-reading, WHOIS lookups and web forms per message. So almost nobody fights back, and the expected cost of hitting any one inbox is roughly zero.

Agents remove the recipient's cost. Tracing the whole stack and filing with every official channel now costs the recipient one sentence. Spammers can't tell which inboxes have an agent behind them. Every send therefore becomes a small lottery ticket for an expensive event: a suspended Workspace tenant, a terminated platform account, the primary domain on a blocklist, a traceback that gets their voice carrier cut off, a regulator file with their name on it, or statutory damages per message.

    expected cost per message = P(recipient is armed) × cost of a full-stack response

Spam stays profitable while that number is below the revenue per message. Agents push P(armed) up. Hitting the whole supply chain, instead of one throwaway address, pushes the cost up. That is the **dark forest** from Liu Cixin's *The Dark Forest*: in a forest full of hunters you can't see, the survival strategy is not to reveal yourself. For senders, "not revealing yourself" means only contacting people who asked to hear from you, which is exactly the behaviour we want.

Two properties keep it a deterrent rather than noise:

- **It only works if reports are right.** Abuse desks, blocklists and regulators all weigh reports by reliability. False reports against senders people actually signed up with teach those systems to discount reports, and that would chill legitimate senders without touching spammers. Precision is the weapon, which is why the ground rules in `SKILL.md` are strict.
- **It runs entirely on official channels.** Every channel below exists to receive these reports and already has thresholds, penalties and enforcement behind it. Those systems haven't been short of authority; they've been short of input, because reporting was tedious. No vigilante action is needed or wanted.

---

## Email: cold outreach and spam

### 1. Lead data: where your address came from

- **What it is:** Enrichment vendors and data brokers (Apollo, ZoomInfo, Lusha, Cognism, RocketReach, Hunter, …), "waterfall" enrichment tools, and scraped or bought lists. One vendor sells the same address to hundreds of senders.
- **Official channel:** a data-deletion or opt-out request: GDPR Art. 17 (erasure) or Art. 21 (objection to direct marketing, which is absolute), CCPA/CPRA deletion, or the vendor's own opt-out form. **California residents:** [DROP](https://privacy.ca.gov/drop/) (Delete Act) sends one deletion request to 600+ registered data brokers. Brokers must process DROP requests every 45 days from August 2026.
- **What a report does:** It barely hurts *this* sender. It removes you from the supply for *every future* sender who buys from that vendor, so it's the most durable win for the user. It also adds compliance cost for vendors whose business is selling contact data.
- **How to identify the vendor:** It's usually invisible. Guess from the type of sender (B2B SaaS → Apollo/ZoomInfo/Lusha are the usual suspects), ask the sender where they got the address (GDPR Art. 15 gives a right to know the source), and send deletion requests to the top few vendors. Deletion requests are legitimate even when you can't prove the source.

### 2. Sending domains: the throwaway layer

- **What it is:** Cold emailers rarely send from their main domain. They register lookalikes by the dozen (`getacme.com`, `acmehq.io`, `tryacme.co`) at cheap registrars and send from those, so complaints land on the lookalikes and not on the brand.
- **Official channels:** The registrar's abuse contact (in WHOIS/RDAP). ICANN's Registrar Accreditation Agreement (§3.18) requires accredited registrars to keep an abuse contact and to investigate and respond to reports. Domain blocklists: Spamhaus DBL, SURBL, URIBL.
- **What a report does:** Registrars act quickly on phishing and malware but often don't suspend for plain unsolicited marketing, so set expectations accordingly. The bigger effect comes from blocklists: a listed sending domain becomes toxic at most receivers, which wastes the weeks of warmup invested in it.
- **Cost to them:** Each domain is cheap to *buy*. A domain that *delivers* represents weeks of warmup, and a burned one has to be replaced and re-warmed.

**Find the persistent asset.** Operations rotate sending domains specifically so that reports against them don't matter. What they *can't* rotate cheaply is where the money or the replies go: the **Reply-To inbox** (an older domain, or a fixed QQ/Gmail address), the **website or brand domain** in the links, and the **sending-platform account** that sends from every rotated domain. Real example from testing this skill: a predatory "conference" operation sent from two lookalike domains that were 171 and 311 days old, both registered at the same registrar and sent through the same hosted-mail provider. Both pointed replies to a third domain, 567 days old, that never appeared as a sender. Reporting the sending domains alone would cost them a few dollars; including the Reply-To domain and the shared sending account goes after what they actually keep. `parse-headers.py` flags Reply-To mismatches and `recon.sh` prints domain age, which makes this pattern quick to spot.

### 3. Mailboxes: their production capacity

- **What it is:** Google Workspace or Microsoft 365 seats on those lookalike domains, often bought pre-warmed from inbox resellers. Each sends only tens of emails a day to stay under the radar, and is "warmed" for weeks through warmup networks that fake engagement.
- **How to identify:** Headers show `Received: from mail-*.google.com` (Google) or `*.outbound.protection.outlook.com` (Microsoft). `parse-headers.py` flags both, and the sending domain's MX record (`recon.sh`) usually confirms it.
- **Official channels:**
  - *Google Workspace:* Google monitors `abuse@<domain>` and `postmaster@<domain>` for **every** Workspace domain ([source](https://knowledge.workspace.google.com/admin/gmail/spam-and-abuse-policy-in-gmail)), so send the report to `abuse@<sending-domain>` with the original attached. The [Gmail abuse form](https://support.google.com/mail/contact/abuse) also works for gmail.com senders. The Google Workspace/Cloud Acceptable Use Policy prohibits using the services "to generate, distribute, publish or facilitate unsolicited mass email" and also prohibits reselling end-user accounts.
  - *Microsoft:* forward with full headers to `abuse@outlook.com`. For Microsoft 365 tenants, Microsoft has historically redirected reporters to a different tenant-abuse address; follow its reply.
  - *Your own mailbox:* "Report spam" in Gmail, or "Report → Junk" in Outlook. Gmail's help page says that when you report spam *or move an email into Spam*, Google receives a copy and may analyze it.
- **What a report does:** Google says it can suspend the offending user or, if the problem is domain-wide, the entire Workspace account. Separately, every spam report feeds the sending domain's reputation. Gmail tells senders to keep their user-reported spam rate below 0.10% and never reach 0.30%. A mailbox sending a few dozen emails a day has a tiny denominator, so a single report is a large fraction of its traffic. Cold email's low-volume-per-inbox strategy makes each complaint count for more.
- **Cost to them:** Suspended seats, plus the warmup time sunk into them, plus the domain's Gmail reputation. This is their sending capacity.

### 4. The sending platform: sequencer or ESP

- **What it is:** The software that runs the campaign. *Sequencers* (Instantly, Smartlead, lemlist, Apollo, Outreach, Salesloft, HubSpot sequences) drive the connected mailboxes. *Email service providers (ESPs)* (SendGrid, Mailgun, Amazon SES, Mailchimp, Postmark, Brevo, …) send from their own IPs.
- **Look for the platform's own abuse channel first.** Many platforms embed one in every message. Instantly adds `X-Mail-Abuse-Inquiries: https://app.instantly.ai/privacy/report-abuse/<message-id>`, which ties the report to the exact sending account. Mailchimp adds `X-Report-Abuse` with the account and campaign IDs, and HubSpot adds `X-Report-Abuse-To`. A `Feedback-ID` header (SES, Alibaba DirectMail, Mailgun, …) identifies the sending account. In testing on a real Spam folder, 14 of 40 messages carried one of these.
- **How to identify:** ESPs leave header fingerprints (`X-SG-EID`, `X-Mailgun-*`, `amazonses.com`, …). Sequencers show up in **tracking links**: the click/open-tracking hostname is a CNAME to the platform. Examples: `inst.<domain>` → `prox.itrackly.com` (Instantly); → `open.sleadtrack.com` (Smartlead); → `custom.lemlist.com` (lemlist). `parse-headers.py` resolves these automatically.
- **Official channel:** The platform's abuse or trust-and-safety contact (see `report-targets.md`).
- **What a report does:** ESPs send many customers' mail from shared IP pools, so one customer's complaints hurt everyone's delivery. Their acceptable-use policies ban purchased or scraped lists, which is **stricter than the law**, and they terminate accounts over complaint rates. Example: [Alibaba Cloud DirectMail's usage policy](https://www.alibabacloud.com/help/en/direct-mail/getting-started/product-rules/) explicitly prohibits unsolicited "developer letters" (cold outreach). It says that when a recipient reports a message as spam, *all* sender addresses on that Alibaba Cloud account in the region are frozen, and that third-party complaints about large volumes of spam can get the account [permanently banned](https://www.alibabacloud.com/help/en/direct-mail/getting-started/account-ban-rules). Sequencers sell cold email as a product, so they tolerate more. But their shared tracking domains and warmup pools depend on not hosting the worst actors, and repeated reports flag an account.
- **Cost to them:** Termination means losing campaigns, sequences, lead lists, analytics and often a prepaid plan, and a new account means new KYC. This is the highest-leverage report for ESP-sent mail.

### 5. The primary brand domain: the expensive one

- **What it is:** The company's real domain: the one in the signature, the "book a demo" link, the landing page, and often a tracking subdomain of it.
- **Official channels:** Domain blocklists match domains found **anywhere in the message body**: Spamhaus DBL (via the [Spamhaus submission portal](https://submit.spamhaus.org), free account), SURBL and URIBL. Use Google Safe Browsing only if the page is actually deceptive.
- **What a report does:** Sending from lookalikes protects the *sender* domain but not the domain they link to. A blocklist listing of the primary domain degrades **all** mail that mentions it, including the company's own transactional email, invoices and replies to real customers.
- **Cost to them:** Delisting plus months of rebuilt reputation. This is the dark forest's sharpest edge for "legitimate" companies that spam. Blocklists list on their *own* evidence (spam traps, their own data, corroboration), so your submission is evidence for them to weigh, not an order. Be accurate, and expect nothing from a single report.

### 6. Hosting, DNS and CDN

- **What it is:** Where the landing page and DNS live (AWS, Cloudflare, DigitalOcean, Hetzner, Vercel, …).
- **Official channel:** The provider's abuse contact or form.
- **What a report does:** Little, for plain spam. Hosts act fast on phishing, malware and illegal content, rarely on a marketing site whose owner sends spam. Cloudflare generally forwards complaints to the origin host rather than acting itself. **Exception:** a sender running its own SMTP server on a VPS. Then the VPS provider effectively *is* the ESP, and VPS policies (many block port 25 by default) lead to quick termination of spammers.

### 7. Payment rails (when spam sells goods directly)

- **What it is:** The merchant account, payment processor and card network behind a spam-advertised storefront. Per Click Trajectories, this is the chokepoint for affiliate and scam storefronts.
- **Official channel:** The processor's fraud or abuse report (e.g. Stripe, PayPal), or a dispute through your card issuer if you were charged.
- **What a report does:** It matters for scam and affiliate storefronts, where merchant accounts are scarce and slow to replace. It's irrelevant for B2B SaaS cold outreach, whose payment accounts are legitimate. Don't use it there.

### 8. The company itself: regulators and the law

Know which rules apply before claiming a violation:

- **US: CAN-SPAM is an *opt-out* law.** Unsolicited commercial email is **not illegal by itself**. Violations are specific: false or misleading header information, deceptive subject lines, failure to identify the message as an ad (unless the recipient consented), no valid physical postal address, no working opt-out, or an opt-out not honored within 10 business days. Penalties are up to **$53,088 per email** (2025 level, adjusted each January), and both the advertiser and the sender can be liable. The FTC enforces it; recipients can't sue under CAN-SPAM (email providers can). Forward to `spam@uce.gov`; ReportFraud.ftc.gov reports are shared with over 2,000 law-enforcement agencies through Consumer Sentinel.
- **US states:** California B&P §17529.5: recipients can sue for **$1,000 per email** for falsified, misrepresented or forged header information (including sender domains that neither identify the sender nor are traceable through WHOIS, per *Balsam v. Trancos*, 2012), or for subject lines likely to mislead about a material fact. Washington CEMA (RCW 19.190): **$500 per email** to Washington residents for misrepresented origin or *any* false or misleading information in the subject line (*Brown v. Old Navy*, Wash. 2025); mere puffery doesn't count.
- **EU/EEA:** The ePrivacy Directive (Art. 13) requires prior consent for email marketing to individuals, with a "soft opt-in" for existing customers. B2B rules vary by member state (Germany is strict; others allow cold email to corporate addresses). File complaints with the data protection authority under GDPR Art. 77.
- **UK (PECR):** Individuals and sole traders need to have consented. **Corporate addresses** (name@company.com) can lawfully be cold-emailed if the sender identifies itself and offers an opt-out. Don't file an ICO complaint about a compliant B2B email to a work address.
- **Canada (CASL):** Consent-based, including B2B, with implied-consent exceptions (e.g. a conspicuously published address relevant to the person's role). Penalties go up to C$10M per violation for businesses. Report to the [Spam Reporting Centre](https://www.fightspam.gc.ca/src).
- **What a report does:** Regulators rarely act on one complaint; they act on aggregated patterns. Your complaint is a data point that makes a pattern visible. It matters most against repeat or high-volume operations.

**The opt-out tactic (identifiable, real businesses only).** Because US law is opt-out, the cleanest violation you can document is *continued mail after an opt-out*. For a sender that is a real, identifiable company, use the official opt-out once: the `List-Unsubscribe` header (mailto or one-click), or a one-line reply asking to be removed. Log the date. Any message after 10 business days is a §7704(a)(4) violation and strengthens every later report. Never do this with scams or phishing, where any interaction only confirms the address is live.

### Compromised senders (the "sender" is a victim)

Advance-fee and "collaboration request" scams often send from **hacked legitimate websites** on shared hosting. The tells: the From domain is an old business with nothing to do with the pitch, the trusted hop is a shared-hosting server (e.g. `vpsNNNN.<host>.com`), cPanel's `X-AntiAbuse` headers name the server and account, and the Reply-To is a freemail inbox. Here the persistent assets are the **freemail inbox** (report it to its provider; Gmail has an abuse form) and the scammer's access to that server (report it to the host as a compromised account, quoting the `X-AntiAbuse` lines). Blocklist-reporting the victim's domain would punish the wrong party. Consider notifying the domain owner through its website's contact address, since they may not know.

### Predatory journals and conferences

These are a distinct, very common genre for anyone who has published: "Dear Dr. X, we invite you to speak on *[your actual paper title]*". The operations scrape publication titles, run dozens of near-identical event and journal brands, rotate sending domains, and usually send through cheap hosted mail or a bulk-mail platform. Treat them as Category C (anonymous/deceptive commercial spam). Never reply, even to opt out; the reply inbox is the lead-qualification step. The high-value reports are to the **sending platform** (where its policy bans unsolicited mail), the **Reply-To and website domains** (blocklists, where these operations are often absent), and the registrar.

### Phishing (different priorities)

For phishing, speed of takedown matters more than deterrence. Two traps from testing: the **From domain may not exist** (e.g. a made-up TLD), so report the authenticated domains (DKIM `d=`, Return-Path) and the verified sending IP instead. And the **payload is often hosted on a legitimate platform** (a Google Cloud Storage bucket, Firebase, Azure Blob, Cloudflare R2/Pages, GitHub Pages), so report the exact URL to that platform's abuse channel and to Safe Browsing. The platform's domain is not the spammer's brand. Also check the `Received` chain: lines below the hop your own server recorded can be forged to point at innocent third parties. Registrars and hosts act quickly on phishing. Google Safe Browsing and Microsoft SmartScreen listings warn browser users within hours. APWG (`reportphishing@apwg.org`) shares reports with security vendors and takedown services. Report impersonation of a brand to that brand's own abuse or security address too, since it has the strongest incentive to get the site taken down.

---

## Calls: robocalls and telemarketing

### 1. The seller (the beneficiary)

- **What it is:** The company whose product is pitched: auto warranty, insurance, debt relief, solar, Medicare plans. It usually buys calls or leads from lead generators and call centers.
- **Why it matters:** The seller has the money and the persistent identity. Under the TCPA, sellers can be held liable for calls made on their behalf (FCC 2013 *DISH Network* declaratory ruling). Complaints that **name the seller** (from the voicemail, the callback script or the website you're pointed to) are far more actionable than ones that list only a number.
- **Official channels:** FTC (DoNotCall.gov / ReportFraud.ftc.gov), FCC, and the state attorney general. If the user wants to pursue it, a private action (see "Optional: legal escalation" in `SKILL.md`).

### 2. The originating or gateway voice provider: the chokepoint

- **What it is:** The VoIP carrier that put the call onto the US network, or the *gateway* provider for calls from abroad.
- **The machinery:** US voice providers must certify in the FCC's **Robocall Mitigation Database (RMD)**, implement STIR/SHAKEN caller-ID authentication, and answer traceback requests. The **Industry Traceback Group** traces illegal calls hop by hop back to the provider that originated them. When a provider is removed from the RMD, every other US provider must stop accepting its traffic. In August 2025 the FCC removed 185 providers, then over 1,200 more, "effectively disconnecting them from U.S. phone network" ([FCC](https://docs.fcc.gov/public/attachments/DOC-414073A1.pdf)). A bipartisan group of 51 state attorneys general followed with Operation Robocall Roundup.
- **What a report does:** Consumer complaints to the FTC and FCC, together with carrier analytics, are how campaigns get prioritized for traceback. A provider facing removal from the network drops robocalling customers quickly.
- **Cost to them:** For the provider, it's the death penalty. For the robocaller, it means finding a new carrier willing to risk the same.

### 3. Caller-ID numbers

- **What it is:** Rented or spoofed numbers, rotated constantly.
- **Official channel:** DoNotCall.gov reports. The FTC releases reported numbers every business day to carriers and call-blocking and call-labeling partners.
- **What a report does:** It feeds the "Spam Likely" / "Scam Likely" labels and the blocking. Robocall economics run on answer rate, so a labeled number's answer rate collapses and the number is burned.

### 4. Your carrier and phone

Block the number and report it in the phone's or carrier's spam tool. This feeds the same analytics and protects other subscribers too.

## Texts

1. **Registration layer:** Business texting (A2P) on US carriers must be registered: 10DLC brands and campaigns through The Campaign Registry, toll-free verification, and short-code audits. Carriers watch complaint (7726) and opt-out rates for each campaign. They suspend offending campaigns and can penalize the platform that carried them.
2. **The messaging platform (CPaaS):** Twilio, Bandwidth, Telnyx, Sinch, Vonage, Plivo, …. Identify it with a carrier lookup on the sending number (the "carrier" is often the CPaaS), then report to its abuse channel. Twilio: [twilio.com/en-us/help/abuse](https://www.twilio.com/en-us/help/abuse) or `stopspam@twilio.com`. These platforms answer to carriers and terminate quickly.
3. **Links in the text:** Report to the registrar, Google Safe Browsing, and the URL shortener's abuse page if a shortener was used.
4. **iMessage/RCS spam (not carrier SMS):** "Report Junk" in Apple Messages sends the sender and message to Apple. Use "Report spam" in Google Messages.
5. **Regulators:** The same as for calls (FCC, FTC), plus national regulators (see `report-targets.md`).

---

## Where reports don't bite (be honest with the user)

- **Offshore scam operations on throwaway infrastructure** (botnets, bulletproof hosting, fast-flux DNS) don't care about regulators or blocklists. For these, the value is *protective*: phishing takedowns, Safe Browsing listings and number labeling protect the next victim. Don't promise punishment.
- **A single report rarely changes anything on its own.** These systems act on aggregates. Every accurate report raises the probability that the aggregate crosses a threshold, and that probability, multiplied across many armed recipients, is the deterrent.
- **Abuse desks rarely reply,** and the FTC and FCC don't resolve individual complaints. Look for these success signals instead: the mail or calls stop, a domain shows up on a blocklist, a number gets labeled, or a ticket is closed with action taken.
