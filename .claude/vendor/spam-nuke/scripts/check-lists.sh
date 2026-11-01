#!/usr/bin/env bash
# check-lists.sh — Read-only blocklist status for domains and IPs (DNS lookups only).
# Usage: check-lists.sh <domain-or-ip> [<domain-or-ip> ...]
#
# Use it twice: BEFORE filing (is this already listed? an unlisted obvious spammer means
# your blocklist report adds new evidence) and ~2 weeks AFTER (did anything change? —
# a new listing is one of the few visible success signals).
#
# Domains: Spamhaus DBL, SURBL, URIBL.  IPs: Spamhaus ZEN, SpamCop.
# These services refuse queries from big public resolvers (8.8.8.8, 1.1.1.1, …) and
# answer with an error code instead — reported below as "QUERY REFUSED", not "clean".
# Requires: dig. Bash 3.2+ (macOS default works).

set -uo pipefail
[ $# -ge 1 ] || { echo "Usage: check-lists.sh <domain-or-ip> ..."; exit 1; }
command -v dig >/dev/null 2>&1 || { echo "dig is required"; exit 1; }

q() { dig +short +time=4 +tries=1 A "$1" 2>/dev/null | grep -E '^[0-9.]+$' | head -1; }
qall() { dig +short +time=4 +tries=1 A "$1" 2>/dev/null | grep -E '^[0-9.]+$'; }

dbl_meaning() {
    case "$1" in
        "") echo "not listed" ;;
        127.0.1.2) echo "LISTED — spam domain" ;;
        127.0.1.4) echo "LISTED — phishing domain" ;;
        127.0.1.5) echo "LISTED — malware domain" ;;
        127.0.1.6) echo "LISTED — botnet C&C domain" ;;
        127.0.1.10[2-6]) echo "LISTED — abused legit domain ($1)" ;;
        127.0.1.255) echo "error — IP queried against DBL" ;;
        127.255.255.*) echo "QUERY REFUSED ($1: public/open resolver or rate limit — result unknown)" ;;
        *) echo "LISTED ($1)" ;;
    esac
}
zen_meaning() {
    case "$1" in
        "") echo "not listed" ;;
        127.0.0.2) echo "LISTED — SBL (spam source)" ;;
        127.0.0.3) echo "LISTED — SBL CSS (snowshoe spam)" ;;
        127.0.0.[4-7]) echo "LISTED — XBL (exploited/botnet host)" ;;
        127.0.0.9) echo "LISTED — DROP (hijacked/criminal netblock)" ;;
        127.0.0.1[01]) echo "PBL only (dynamic/end-user range policy — NOT a spam listing)" ;;
        127.255.255.*) echo "QUERY REFUSED ($1: public/open resolver or rate limit — result unknown)" ;;
        *) echo "LISTED ($1)" ;;
    esac
}
surbl_meaning() {
    case "$1" in
        "") echo "not listed" ;;
        127.0.0.1) echo "QUERY REFUSED (127.0.0.1: blocked/over free limit — result unknown)" ;;
        *) echo "LISTED ($1; 8=phish 16=malware 64=abuse 128=cracked, summed)" ;;
    esac
}
uribl_meaning() {
    case "$1" in
        "") echo "not listed" ;;
        127.0.0.1) echo "QUERY REFUSED (127.0.0.1: public resolver/over limit — result unknown)" ;;
        *) echo "LISTED ($1; 2=black 4=grey 8=red, summed)" ;;
    esac
}

for T in "$@"; do
    T=$(printf '%s' "$T" | sed -E 's#^[a-zA-Z]+://##; s#[/:].*$##' | tr '[:upper:]' '[:lower:]')
    echo "== $T"
    if printf '%s' "$T" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
        R=$(printf '%s' "$T" | awk -F. '{print $4"."$3"."$2"."$1}')
        Z=$(qall "$R.zen.spamhaus.org")
        if [ -z "$Z" ]; then echo "  Spamhaus ZEN : not listed"
        else for c in $Z; do echo "  Spamhaus ZEN : $(zen_meaning "$c")"; done; fi
        S=$(q "$R.bl.spamcop.net")
        echo "  SpamCop      : $([ -n "$S" ] && echo "LISTED ($S)" || echo "not listed")"
        echo "  (AbuseIPDB history: https://www.abuseipdb.com/check/$T)"
    else
        echo "  Spamhaus DBL : $(dbl_meaning "$(q "$T.dbl.spamhaus.org")")"
        echo "  SURBL        : $(surbl_meaning "$(q "$T.multi.surbl.org")")"
        echo "  URIBL        : $(uribl_meaning "$(q "$T.multi.uribl.com")")"
    fi
done
echo ""
echo "Not listed ≠ clean: lists need evidence. An obvious spammer that isn't listed is exactly where a report adds information."
