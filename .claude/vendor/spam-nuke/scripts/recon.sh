#!/usr/bin/env bash
# recon.sh — Map a sender's infrastructure from their domain.
# Usage: recon.sh <domain>
# Output: structured summary of the providers in their supply chain.
# Requires: dig, whois (optional but recommended). Bash 3.2+ (macOS default works).

set -uo pipefail

DOMAIN="${1:?Usage: recon.sh <domain>}"
# Strip protocol/path/port and lowercase, in case a URL was pasted
DOMAIN=$(printf '%s' "$DOMAIN" | sed -E 's#^[a-zA-Z]+://##; s#[/:].*$##' | tr '[:upper:]' '[:lower:]')

echo "============================================"
echo "  SPAM NUKE RECON: $DOMAIN"
echo "  $(date -u '+%Y-%m-%d %H:%M UTC')"
echo "============================================"
echo ""

# --- WHOIS ---
echo "## WHOIS / Registrar"
echo "---"
if command -v whois >/dev/null 2>&1; then
    WHOIS_OUT=$(whois "$DOMAIN" 2>/dev/null | LC_ALL=C tr -d '\r' || true)
    REGISTRAR=$(printf '%s\n' "$WHOIS_OUT" | grep -i "^ *registrar:" | head -1 | sed 's/^[^:]*: *//')
    ABUSE_EMAIL=$(printf '%s\n' "$WHOIS_OUT" | grep -i "abuse.*email" | head -1 | sed 's/^[^:]*: *//')
    ABUSE_PHONE=$(printf '%s\n' "$WHOIS_OUT" | grep -i "abuse.*phone" | head -1 | sed 's/^[^:]*: *//')
    # Prefer the registry's "Creation Date:"; the IANA header's "created: 1985-01-01" is the TLD's, not the domain's
    CREATION=$(printf '%s\n' "$WHOIS_OUT" | grep -i "creation date:" | head -1 | sed 's/^[^:]*: *//')
    [ -z "$CREATION" ] && CREATION=$(printf '%s\n' "$WHOIS_OUT" | sed -n '/^refer:/,$p' | grep -iv "^created: *1985" | grep -i "^ *created:\|registered on:\|registration time:" | head -1 | sed 's/^[^:]*: *//')
    echo "Registrar: ${REGISTRAR:-[not found]}"
    echo "Abuse Email: ${ABUSE_EMAIL:-[not found]}"
    echo "Abuse Phone: ${ABUSE_PHONE:-[not found]}"
    echo "Domain Created: ${CREATION:-[not found]}"
    if [ -n "$CREATION" ]; then
        CY=$(printf '%s' "$CREATION" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1)
        if [ -n "$CY" ]; then
            AGE_DAYS=$(python3 -c "import datetime as d,sys; print((d.date.today()-d.date.fromisoformat(sys.argv[1])).days)" "$CY" 2>/dev/null || echo "")
            [ -n "$AGE_DAYS" ] && echo "Domain Age: ${AGE_DAYS} days$([ "$AGE_DAYS" -lt 365 ] 2>/dev/null && echo '  ⚠️  under a year old')"
        fi
    fi
    echo "(Created in the last few weeks/months + a lookalike name = likely a burner sending domain."
    echo " Report it, but also find the BRAND domain in the email's links and run recon on that too.)"
else
    echo "[whois not installed — use https://lookup.icann.org/en/lookup?name=$DOMAIN]"
fi
echo ""

# --- DNS Records ---
echo "## DNS Records"
echo "---"

echo "### A Records (hosting)"
A_RECORDS=$(dig +short A "$DOMAIN" 2>/dev/null | grep -E '^[0-9.]+$' || true)
echo "${A_RECORDS:-[none]}"
if [ -n "$A_RECORDS" ] && command -v whois >/dev/null 2>&1; then
    FIRST_IP=$(printf '%s\n' "$A_RECORDS" | head -1)
    IP_WHOIS=$(whois "$FIRST_IP" 2>/dev/null | LC_ALL=C tr -d '\r' || true)
    IP_ORG=$(printf '%s\n' "$IP_WHOIS" | LC_ALL=C grep -i "^ *\(orgname\|org-name\|netname\|descr\)" | head -2 | sed 's/^[^:]*: *//' | tr '\n' ' ')
    IP_ABUSE=$(printf '%s\n' "$IP_WHOIS" | LC_ALL=C grep -i "abuse" | LC_ALL=C grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' | head -1)
    echo "IP Owner: ${IP_ORG:-[not found]}"
    echo "IP Abuse Contact: ${IP_ABUSE:-[not found]}"
fi
echo ""

echo "### NS Records (DNS provider)"
dig +short NS "$DOMAIN" 2>/dev/null || echo "[dig failed]"
echo ""

echo "### MX Records (email receiving — also reveals the mailbox provider)"
MX=$(dig +short MX "$DOMAIN" 2>/dev/null || true)
echo "${MX:-[no MX record]}"
if printf '%s' "$MX" | grep -qi 'google\.com\|googlemail\.com'; then
    echo "  ✓ Mailboxes on Google Workspace → report to abuse@$DOMAIN (Google monitors abuse@/postmaster@"
    echo "    on every Workspace domain) + https://support.google.com/mail/contact/abuse"
elif printf '%s' "$MX" | grep -qi 'outlook\.com\|protection\.outlook'; then
    echo "  ✓ Mailboxes on Microsoft 365 → report to abuse@outlook.com (Microsoft may redirect tenant abuse)"
elif printf '%s' "$MX" | grep -qi 'zoho'; then
    echo "  ✓ Mailboxes on Zoho → abuse@zohocorp.com"
fi
echo ""

echo "### SPF Record (authorized senders — key for identifying sending platforms)"
SPF=$(dig +short TXT "$DOMAIN" 2>/dev/null | grep -i "v=spf1" || true)
echo "${SPF:-[no SPF record]}"
echo ""

echo "### DMARC Record"
DMARC=$(dig +short TXT "_dmarc.$DOMAIN" 2>/dev/null || true)
echo "${DMARC:-[no DMARC record]}"
echo ""

echo "### DKIM Selectors (common)"
for SELECTOR in default google s1 s2 selector1 selector2 k1 k2 k3 dkim mail sg sg1 pm mandrill mxvault smtp; do
    DKIM=$(dig +short TXT "${SELECTOR}._domainkey.$DOMAIN" 2>/dev/null)
    # Only real keys (p=) or delegations (CNAME to *domainkey*); skips wildcard TXT noise
    if [ -n "$DKIM" ] && printf '%s' "$DKIM" | grep -qi 'p=\|domainkey'; then
        echo "  ${SELECTOR}._domainkey: $(printf '%s' "$DKIM" | tr '\n' ' ' | cut -c1-140)"
    fi
done
echo ""

echo "### CNAME Records (CDN / tracking / landing pages)"
for SUB in www mail app link links click track email go; do
    CNAME=$(dig +short CNAME "${SUB}.$DOMAIN" 2>/dev/null)
    if [ -n "$CNAME" ]; then
        echo "  ${SUB}.$DOMAIN → $CNAME"
    fi
done
echo ""

# --- Sending-platform detection from SPF ---
# "pattern|label" pairs (no associative arrays, so this runs on macOS bash 3.2)
echo "## Detected Providers (from SPF)"
echo "---"
if [ -n "$SPF" ]; then
    FOUND=0
    while IFS='|' read -r PATTERN LABEL; do
        [ -z "$PATTERN" ] && continue
        if printf '%s' "$SPF" | grep -qi "$PATTERN"; then
            echo "  ✓ $LABEL"
            FOUND=1
        fi
    done << 'EOF'
sendgrid.net|SendGrid (Twilio) — abuse@sendgrid.com
mailgun.org|Mailgun — abuse@mailgun.com
amazonses.com|AWS SES — email-abuse@amazon.com
postmarkapp.com|Postmark — support@postmarkapp.com
mcsv.net|Mailchimp — abuse@mailchimp.com
mandrillapp.com|Mailchimp Transactional (Mandrill) — abuse@mailchimp.com
hubspot|HubSpot — abuse@hubspot.com
constantcontact.com|Constant Contact — abuse@constantcontact.com
brevo.com|Brevo — abuse@brevo.com
sendinblue.com|Brevo (Sendinblue) — abuse@brevo.com
activecampaign.com|ActiveCampaign — abuse@activecampaign.com
sparkpostmail.com|SparkPost — abuse@sparkpost.com
klaviyo|Klaviyo — compliance@klaviyo.com
convertkit|Kit (ConvertKit) — support@convertkit.com
freshworks|Freshworks — support@freshworks.com
outreach.io|Outreach — abuse@outreach.io
salesloft|Salesloft — abuse@salesloft.com
zoho|Zoho Mail — abuse@zohocorp.com
_spf.google.com|Google Workspace — report via https://support.google.com/mail/contact/abuse
outlook.com|Microsoft 365 — abuse@microsoft.com
EOF
    [ "$FOUND" -eq 0 ] && echo "  [no known platforms matched — inspect SPF includes manually]"
else
    echo "  [no SPF record]"
fi
echo ""

echo "## Blocklist status (read-only)"
bash "$(dirname "$0")/check-lists.sh" "$DOMAIN" 2>/dev/null | grep -E "^  " || echo "  [check-lists.sh unavailable]"
echo ""

echo "## Abuse contact aggregator"
echo "  https://www.abuse.net/lookup.phtml?domain=$DOMAIN"
echo ""
echo "============================================"
echo "  RECON COMPLETE"
echo "  Next: compare with the email headers — the"
echo "  sending platform often isn't visible in DNS."
echo "============================================"
