# Spam Report Targets — Full Reference

Abuse endpoints, filing URLs and instructions for each target in the spam-nuke checklist: email, phishing, calls and texts.

> Abuse addresses and form URLs change. Treat this as a starting point: confirm the current contact on the provider's own abuse/trust page or via https://www.abuse.net before sending, and update this file when one has moved.

For *why* each layer matters and what a report there costs the sender, see `supply-chain.md`.

## Platform-Provided Abuse Channels (check the headers first)

Sending platforms often embed their own abuse channel in the message. These are the most precise reports possible because they identify the exact account. `parse-headers.py` lists them under ★.

| Header | Platform | What it gives you |
|---|---|---|
| `X-Mail-Abuse-Inquiries` | Instantly | Per-message report URL (`app.instantly.ai/privacy/report-abuse/<message-id>`) |
| `X-Report-Abuse` | Mailchimp | Per-campaign report URL with account (`u=`) and campaign (`id=`) IDs |
| `X-Report-Abuse-To` | HubSpot and others | The platform's abuse address + policy link |
| `X-AntiAbuse` | cPanel/Exim shared hosting | Server hostname, account UID/GID, sender domain: quote verbatim to the host |
| `Feedback-ID` / `X-Feedback-Id` | Amazon SES, Alibaba DirectMail, Mailgun, … | Identifies the sending account/campaign at the platform: include it in the platform report |

## Freemail Reply-To Inboxes (the operation's persistent inbox)

When replies go to a free mailbox, that inbox is often the one asset the operation can't rotate. Report the address to its provider:

| Provider | Report to |
|---|---|
| Gmail | https://support.google.com/mail/contact/abuse |
| Outlook / Hotmail / Live | abuse@outlook.com |
| Tuta (tutamail.com, tutanota.com, tuta.io) | abuse@tutao.de (per tuta.com/support) |
| QQ Mail (Tencent) | spam@qq.com (Tencent's spam-report inbox) |

## Mailbox Providers (where most cold email actually comes from)

Modern cold email is sent from Google Workspace / Microsoft 365 seats on lookalike domains, not from an ESP. `parse-headers.py` and `recon.sh` (MX) detect this.

| Provider | How to report | Notes |
|---|---|---|
| **Google Workspace** (custom domain) | Forward the original (as attachment) to **`abuse@<sending-domain>`**. Google monitors `abuse@` and `postmaster@` on every Workspace domain | [Google's own statement](https://knowledge.workspace.google.com/admin/gmail/spam-and-abuse-policy-in-gmail): it may suspend the user, or the whole Workspace account if the problem is domain-wide. AUP bans "unsolicited mass email" and reselling end-user accounts |
| **Gmail** (consumer) | https://support.google.com/mail/contact/abuse | Paste full headers |
| **Outlook.com / Hotmail / Live** | Forward with full headers to `abuse@outlook.com` | For Microsoft 365 tenants Microsoft may reply redirecting you to a tenant-abuse address — follow it |
| **Zoho Mail** | abuse@zohocorp.com | |
| **Your own client** | Gmail "Report spam" (or move to Spam); Outlook "Report → Junk" | Gmail: reporting *or moving to Spam* sends Google a copy. Feeds the sender's domain reputation (Gmail wants senders under 0.1% reported-spam rate, never 0.3%) |

## Sequencer Fingerprints (from tracking links)

Sequencers drive the mailboxes above; they show up in click/open-tracking links. A custom tracking subdomain CNAMEs to the platform. `parse-headers.py` resolves these automatically.

| Platform | Tracking fingerprint | Abuse contact |
|---|---|---|
| **Instantly** | `inst.<domain>` → CNAME `prox.itrackly.com`; shared tracking host `*.inreg1.com` | support@instantly.ai |
| **Smartlead** | `<host>.<domain>` → CNAME `open.sleadtrack.com` | support@smartlead.ai |
| **lemlist** | `trail.` / `route.` / `lemtrail.` subdomain → CNAME `custom.lemlist.com` | support@lemlist.com |
| **Apollo** | Custom tracking subdomain (value unique per account) | support@apollo.io (+ privacy@apollo.io for deletion) |
| **Mailchimp** | `*.list-manage.com` links | abuse@mailchimp.com |
| **HubSpot** | `*.hubspotlinks.com` links | abuse@hubspot.com |
| **SendGrid** | `*.ct.sendgrid.net` links / CNAME to `sendgrid.net` | abuse@sendgrid.com |

An unrecognised CNAME target: search for it — vendors document their tracking CNAME in their help centre. Add it to this table and to `SEQUENCER_CNAME_TARGETS` in `parse-headers.py`.

## Abused Hosting Platforms (payloads, redirectors, phishing pages)

Report the **exact URL**, not the platform's domain. Add Google Safe Browsing (https://safebrowsing.google.com/safebrowsing/report_phish/) for anything deceptive; browser warnings often land faster than platform takedowns.

| Platform | Report channel |
|---|---|
| Google Cloud Storage (`storage.googleapis.com`), Firebase, App Engine | https://support.google.com/code/contact/cloud_platform_report |
| Google Docs / Forms / Sites | The "Report abuse" link on the page |
| Azure Blob / Static Web (`*.core.windows.net`) | https://msrc.microsoft.com/report/abuse |
| AWS S3 / CloudFront | abuse@amazonaws.com or the AWS abuse form |
| Cloudflare R2 / Pages / Workers (`*.r2.dev`, `*.pages.dev`, `*.workers.dev`) | https://abuse.cloudflare.com |
| GitHub Pages / raw.githubusercontent.com | https://github.com/contact/report-abuse |
| Vercel / Netlify | https://vercel.com/abuse · abuse@netlify.com |

## ESP Abuse Teams

Report with full email headers attached. ESPs send many customers' mail from shared IPs, so their acceptable-use policies (usually banning purchased/scraped lists — stricter than the law) are enforced on complaint rates. Expect no reply; the effect is on the account.

| ESP | Abuse Contact | Notes |
|-----|--------------|-------|
| **SendGrid (Twilio)** | abuse@sendgrid.com | Header fingerprint: `X-SG-EID`, `@sendgrid.net` in Received |
| **Mailgun** | abuse@mailgun.com | Header: `X-Mailgun-Sid`, `@mailgun.org` in Message-ID |
| **AWS SES** | email-abuse@amazon.com | Header: `@amazonses.com` in Message-ID, `X-SES-Outgoing` |
| **Postmark** | support@postmarkapp.com | Header: `X-PM-Message-Id`, strict anti-spam policy |
| **Mailchimp (Intuit)** | abuse@mailchimp.com | Header: `@mail*.mcdlv.net`, `X-MC-User` |
| **HubSpot** | abuse@hubspot.com | Header: `@hubspotemail.net`, tracking links in body |
| **Constant Contact** | abuse@constantcontact.com | Header: `@ccsend.com` |
| **ActiveCampaign** | abuse@activecampaign.com | Header: `@acsend.com` |
| **Brevo (ex-Sendinblue)** | abuse@brevo.com | Header: `@sendinblue.com` |
| **ConvertKit** | support@convertkit.com | Report via their abuse form |
| **Klaviyo** | compliance@klaviyo.com | Header: tracking links with `trk.klaviyomail.com` |
| **Customer.io** | support@customer.io | Header: `@cio.email` |
| **Resend** | support@resend.com | Header: `@resend.dev` |
| **Sparkpost (MessageBird)** | abuse@sparkpost.com | Header: `@sparkpostmail.com` |
| **Mailtrap** | support@mailtrap.io | Header: `@mailtrap.io` |
| **Instantly** | support@instantly.ai | Common cold email tool |
| **Lemlist** | support@lemlist.com | Common cold email tool |
| **Apollo.io** | support@apollo.io | Both enrichment and sending |
| **Outreach.io** | abuse@outreach.io | Sales engagement platform |
| **Salesloft** | abuse@salesloft.com | Sales engagement platform |
| **Smartlead** | support@smartlead.ai | Cold email infrastructure |
| **Woodpecker** | support@woodpecker.co | Cold email tool |
| **Reply.io** | support@reply.io | Sales engagement |
| **Mixmax** | support@mixmax.com | Header: tracking pixels/links from mixmax |
| **Mailshake** | support@mailshake.com | Cold outreach tool |
| **Alibaba Cloud DirectMail** | Alibaba Cloud Reporting Center / Abuse Claim Form (linked from alibabacloud.com's legal/DSA page) | Sending host `*.dm.aliyun.com`; unsubscribe/tracking `dm-*.aliyuncs.com`. Policy bans unsolicited mail incl. cold outreach; third-party complaints can permanently ban the account |
| **Net263 hosted mail (China)** | abuse@link263.com (per a 263 reseller page; verify) | Sending host `*.263.net`; SPF `include:spf.263.net`, MX `mx.263.net` |
| **Salesforce Marketing Cloud / Pardot** | https://security.salesforce.com/report-concern-form (Platform Abuse → Unsolicited Commercial Emails) | Sending host `*.exacttarget.com`; Pardot tracking CNAME → `go.pardot.com`. Anti-spam policy bans purchased/harvested lists |
| **Elastic Email** | https://elasticemail.com/report-spam | Tracking CNAME → `api.elasticemail.com`. AUP requires double opt-in; complaint rate over 0.1% triggers review |

## Blocklists & Spam Databases

| Service | Submission URL/Method | Impact Level |
|---------|----------------------|-------------|
| **SpamCop** | https://www.spamcop.net — create account, submit via email parsing | High — auto-reports to the source network's abuse contact; SCBL listings are automated and short-lived (expire ~24h after reports stop) |
| **Spamhaus SBL/DBL** | https://submit.spamhaus.org — Spamhaus submission portal (free account); submit the IP and the domains (sending + linked) | Critical — used by most major mail systems. Spamhaus lists on its own evidence; a submission is evidence, not an order |
| **SURBL** | http://www.surbl.org — domain URI blocklist | High — matches domains linked in email bodies (this is how the *brand* domain gets hit) |
| **URIBL** | https://uribl.com — URI blocklist | High |
| **Barracuda BRBL** | https://www.barracudacentral.org/lookups — report via lookup tool | Medium |
| **Abusix** | https://www.abusix.com — report via their platform | Medium |
| **abuse.net** | https://www.abuse.net — find abuse contacts for any domain | Utility — aggregates contacts |
| **AbuseIPDB** | https://www.abuseipdb.com/report — report sending IP | Medium |
| **DNSBL.info** | https://www.dnsbl.info — check current listings | Utility — diagnostic |

## Regulatory Bodies

### United States

| Agency | Filing URL | Applicable Law | When to Use |
|--------|-----------|---------------|------------|
| **FTC** | https://reportfraud.ftc.gov (+ forward to spam@uce.gov) | CAN-SPAM Act, FTC Act §5 | Commercial email that actually violates CAN-SPAM (checklist below) or is deceptive. Reports go into Consumer Sentinel, shared with 2,000+ law enforcers |
| **FTC (calls)** | https://www.donotcall.gov/report.html | Telemarketing Sales Rule | Unwanted sales calls / robocalls where no money was lost |
| **FCC** | https://consumercomplaints.fcc.gov | TCPA | Unsolicited calls and texts (Phone → "Unwanted calls/texts") |
| **State AG** | Varies by state | State anti-spam laws | CA (B&P §17529.5) and WA (CEMA) are strongest and give recipients a private right of action. Search "[state] attorney general consumer complaint" |
| **IC3** | https://www.ic3.gov | If phishing/fraud involved | Only for fraudulent emails, not just spam |

**CAN-SPAM is an opt-out law: unsolicited commercial email is *not* a violation by itself.** Cite only what the message shows (each violating email: up to $53,088, the 2025 level, inflation-adjusted every January; advertiser and sender can both be liable):
- False or misleading header information (From, Reply-To, routing, sender domain)
- Deceptive subject line
- No working opt-out mechanism
- Opt-out not honored within 10 business days ← the strongest, cleanest evidence; see the opt-out tactic in `supply-chain.md`
- No valid physical postal address
- Not identified as an advertisement (unless the recipient consented)

Recipients can't sue under CAN-SPAM (email providers can); state laws (CA, WA) fill that gap for falsity/deception.

### European Union / EEA

| Authority | Filing URL | When to Use |
|-----------|-----------|------------|
| **Local DPA** | https://edpb.europa.eu/about-edpb/about-edpb/members_en (directory) | Sender or recipient in EU. File with sender's country DPA. |
| **noyb.eu** | https://noyb.eu/en/exercise-your-rights-article-77-complain-your-dpa | Templates and guidance for GDPR complaints |
| **ICO (UK)** | https://ico.org.uk/make-a-complaint | UK-nexus senders/recipients. PECR: individuals/sole traders need consent; **corporate addresses can lawfully get B2B cold email** with sender ID + opt-out — don't complain about compliant B2B mail to a work address |

**GDPR complaint elements:**
- Cite Article 77 GDPR (right to complain) + the national ePrivacy rule (Art. 13 ePrivacy Directive): email marketing to individuals needs prior consent, with a "soft opt-in" only for existing customers
- B2B varies by member state (Germany strict; some allow cold email to corporate addresses) — check the sender's/recipient's country before asserting a violation
- Art. 21(2)–(3): an objection to direct marketing is absolute; mail after an objection is the cleanest violation
- Art. 15: you can demand the source of your data (often reveals the enrichment vendor)
- Include: sender identity, your data processed, evidence (the email), dates

### Canada

| Authority | Filing URL | When to Use |
|-----------|-----------|------------|
| **Spam Reporting Centre (CASL)** | https://www.fightspam.gc.ca/src | Sender or recipient in Canada. CASL is consent-based incl. B2B (implied-consent exceptions apply); penalties up to C$10M per violation for businesses |

### Australia

| Authority | Filing URL | When to Use |
|-----------|-----------|------------|
| **ACMA** | https://www.acma.gov.au/report-spam | Australian Spam Act 2003 |

### Singapore

| Authority | Filing URL | When to Use |
|-----------|-----------|------------|
| **PDPC** | https://www.pdpc.gov.sg/complaints | Personal Data Protection Act |

## Infrastructure Providers — Abuse Contacts

### Domain Registrars

Look up via WHOIS (`whois <domain>` or https://lookup.icann.org). The abuse contact is in the WHOIS record.

| Registrar | Abuse Contact |
|-----------|--------------|
| **GoDaddy** | abuse@godaddy.com |
| **Namecheap** | abuse@namecheap.com |
| **Cloudflare Registrar** | abuse@cloudflare.com |
| **Google Domains** | registrar-abuse@google.com |
| **Porkbun** | abuse@porkbun.com |
| **Name.com** | abuse@name.com |
| **Hover** | abuse@hover.com |
| **Dynadot** | abuse@dynadot.com |
| **Gandi** | abuse@gandi.net |

### Hosting Providers

Identify via IP WHOIS of A record or sending IP.

| Provider | Abuse Contact |
|----------|--------------|
| **AWS** | abuse@amazonaws.com |
| **Google Cloud** | https://support.google.com/code/contact/cloud_platform_report |
| **Azure/Microsoft** | abuse@microsoft.com |
| **DigitalOcean** | abuse@digitalocean.com |
| **Hetzner** | abuse@hetzner.com |
| **OVH** | abuse@ovh.net |
| **Vultr** | abuse@vultr.com |
| **Linode (Akamai)** | abuse@linode.com |
| **Vercel** | https://vercel.com/abuse |
| **Netlify** | abuse@netlify.com |
| **Render** | abuse@render.com |
| **Railway** | abuse@railway.app |

### CDN Providers

| Provider | Abuse Contact |
|----------|--------------|
| **Cloudflare** | https://www.cloudflare.com/abuse/form |
| **Fastly** | abuse@fastly.com |
| **Akamai** | abuse@akamai.com |

### CRM / Sales Tools

If identifiable (from tracking pixels, link domains, or enrichment data):

| Provider | Abuse Contact | How to Identify |
|----------|--------------|----------------|
| **HubSpot** | abuse@hubspot.com | Tracking links, forms, chat widget |
| **Salesforce** | abuse@salesforce.com | Pardot links, SF tracking |
| **Pipedrive** | support@pipedrive.com | Tracking links |
| **Close.com** | support@close.com | Sales engagement |

### Data Enrichment Providers

Usually invisible — infer from the sender type (B2B SaaS → Apollo/ZoomInfo/Lusha are the usual suspects) and ask the sender for the source (GDPR Art. 15). Deletion requests are legitimate even without proof of source.


| Provider | Abuse/Compliance Contact |
|----------|-------------------------|
| **California DROP** (all registered brokers at once) | https://privacy.ca.gov/drop/ — California residents; one request reaches 600+ registered data brokers, processed every 45 days from Aug 2026 |
| **Apollo.io** | privacy@apollo.io — request data deletion + report |
| **ZoomInfo** | privacy@zoominfo.com |
| **Clearbit (HubSpot)** | privacy@clearbit.com |
| **Lusha** | privacy@lusha.com |
| **RocketReach** | support@rocketreach.co |
| **Hunter.io** | support@hunter.io |
| **Snov.io** | support@snov.io |
| **LeadIQ** | privacy@leadiq.com |
| **Cognism** | privacy@cognism.com |
| **Kaspr** | dpo@kaspr.io |
| **Seamless.ai** | support@seamless.ai |

For all enrichment providers: file a **data deletion request** under GDPR/CCPA in addition to the abuse report. This removes the user's email from their database, preventing future scraping.

### Payment Processors

The chokepoint for scam/affiliate storefronts selling goods directly (merchant accounts are scarce and slow to replace — Levchenko et al. 2011). Irrelevant for B2B SaaS cold outreach:

| Provider | How to Report |
|----------|--------------|
| **Stripe** | https://stripe.com/legal/report-fraud — report a fraudulent or deceptive merchant |
| **PayPal** | https://www.paypal.com/disputes — report if payment/invoice involved |

## Phishing / Fraud (in addition to the above)

| Channel | How | Notes |
|---------|-----|-------|
| Mail client | "Report phishing" (Gmail ⋮ menu, Outlook Report button) | Distinct from "Report spam"; feeds anti-phishing models |
| **APWG** | Forward to reportphishing@apwg.org | Shared with security vendors and takedown services |
| **Google Safe Browsing** | https://safebrowsing.google.com/safebrowsing/report_phish/ | Gets the landing page flagged in Chrome/Firefox/Safari |
| **Microsoft** | https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site | Flags in Edge / SmartScreen |
| Registrar + host | Abuse contacts above, ask for takedown | Phishing gets far faster action than plain spam |
| **IC3 (US)** | https://www.ic3.gov | Only if money or credentials were actually lost |

## Calls & Texts

Gather per call/message: caller-ID number (even if spoofed), the number that received it, date/time, any callback number or company named, transcript/recording/screenshot.

### United States

| Channel | How | Notes |
|---------|-----|-------|
| **FTC DoNotCall.gov** | https://www.donotcall.gov/report.html | Streamlined call report. Reported numbers are published each business day to carriers for call-blocking. Lost money → ReportFraud.ftc.gov instead |
| **FCC** | https://consumercomplaints.fcc.gov → Phone → "Unwanted calls/texts" → "All other unwanted calls/messages" | International numbers go in "Additional Information". Used for enforcement, not individual resolution |
| **Do Not Call Registry** | https://www.donotcall.gov (register/verify) | Confirm the emailed link within 72h. Sales robocalls without written consent are illegal regardless |
| **Carrier** | Forward spam texts to **7726** ("SPAM"); block + report in the phone/carrier spam tool | 7726 works on all major US carriers |
| **Voice / messaging provider (CPaaS)** | Carrier lookup on the number (e.g. Twilio Lookup API or any free carrier-lookup site) → that provider's abuse desk. **Twilio:** https://www.twilio.com/en-us/help/abuse or stopspam@twilio.com. Bandwidth, Telnyx, Sinch, Vonage, Plivo: their own abuse pages | Only for real (non-spoofed) numbers. Providers answer to carriers and FCC rules (Robocall Mitigation Database, traceback); they cut off abusive customers fast |
| **State AG** | Varies by state | Repeat offenders; strong telemarketing laws in e.g. FL, OK, WA |

### Canada

| Channel | How | Notes |
|---------|-----|-------|
| **CRTC National DNCL** | https://lnnte-dncl.gc.ca (file a complaint) | Telemarketing calls — the Spam Reporting Centre does NOT take call complaints |
| **Spam Reporting Centre** | https://www.fightspam.gc.ca/src | Spam texts (CASL covers SMS) and email |
| Carrier | Forward texts to 7726 | Supported by Canadian carriers |

### United Kingdom

| Channel | How | Notes |
|---------|-----|-------|
| **Carrier** | Forward spam texts to 7726 | All UK networks |
| **TPS** | https://www.tpsonline.org.uk (register) | Telephone Preference Service — UK do-not-call list |
| **ICO** | https://ico.org.uk/make-a-complaint/nuisance-calls-and-messages/ | Nuisance calls/texts complaints (PECR) |

### Australia

| Channel | How | Notes |
|---------|-----|-------|
| **ACMA (texts)** | Forward SMS to **0429 999 888** | Standard SMS charges apply |
| **ACMA (email)** | Forward to report@submit.spam.acma.gov.au | Don't edit the message or subject |
| **ACMA (calls)** | https://www.acma.gov.au (Do Not Call Register / telemarketing complaint) | Telemarketing to registered numbers |

### Singapore

| Channel | How | Notes |
|---------|-----|-------|
| **ScamShield app** | Report message / call / website in the app | Calls must have been answered to be reportable. Reviewed by police; confirmed numbers get blocked for all users |
| **PDPC DNC complaint** | https://www.pdpc.gov.sg/complaints-and-reviews/dnc-complaint-form | Telemarketing calls/SMS to a Singapore number |
| **ScamShield Helpline** | 1799 | Advice / bank routing if money was lost; not a police report |

## LinkedIn

If the spammer also reached out on LinkedIn or is identifiable there:
- Report their profile for spam
- Report their company page
- Report individual messages as spam

## Google-Specific

- **Gmail "Report spam" button** (or moving the message to Spam, incl. via API/IMAP) — Google receives a copy; feeds filters and the sender domain's reputation
- **Google Safe Browsing** — https://safebrowsing.google.com/safebrowsing/report_badware/ — if their landing page is deceptive
- **Google Ads** — If they run ads, report via https://support.google.com/ads/troubleshooter/4578507
