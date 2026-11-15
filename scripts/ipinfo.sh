#!/usr/bin/env bash
# Look up the origin ASN of IP addresses with the IPinfo Lite API.
#
# usage: ipinfo.sh <address> [<address> ...]
#
# Prints "<address>\t<asn>\t<as-name>" (e.g. "8.8.8.8	AS15169	Google LLC") for every address with a known ASN.
# Prints nothing when IPINFO_TOKEN is unset, so callers can treat lookups as optional.
#
# env:
#   IPINFO_TOKEN      IPinfo access token (the free Lite plan is enough).
#   IPINFO_CACHE_DIR  cache directory, default "${TMPDIR:-/tmp}/apermon-ipinfo".
#   IPINFO_CACHE_TTL  cache lifetime in seconds, default 86400.
#   IPINFO_TIMEOUT    API timeout in seconds, default 5.

[ -z "$IPINFO_TOKEN" ] && exit 0

cache_dir="${IPINFO_CACHE_DIR:-${TMPDIR:-/tmp}/apermon-ipinfo}"
cache_ttl="${IPINFO_CACHE_TTL:-86400}"
now="`date +%s`"

mkdir -p "$cache_dir" || exit 1

addrs=()
misses=()
for addr in "$@"; do
    # addresses become cache file names; reject anything that is not a plain inet/inet6 address.
    [[ "$addr" =~ ^[0-9a-fA-F:.]+$ ]] || continue
    addrs+=("$addr")

    f="$cache_dir/$addr"
    [ -f "$f" ] && [ $((now - `stat -c %Y "$f"`)) -lt "$cache_ttl" ] && continue
    misses+=("$addr")
done

[ ${#misses[@]} -gt 0 ] && {
    # the batch endpoint takes up to 1000 addresses per request; callers pass at most a few hundred.
    jq -cn '$ARGS.positional' --args "${misses[@]}" |
        curl -sf --max-time "${IPINFO_TIMEOUT:-5}" -H "Authorization: Bearer $IPINFO_TOKEN" \
            -H 'Content-Type: application/json' --data @- 'https://api.ipinfo.io/batch/lite' |
        jq -r 'to_entries[] | select(.value | type == "object") | [.key, .value.asn // "", .value.as_name // ""] | @tsv' |
        while IFS=$'\t' read -r addr asn name; do
            [[ "$addr" =~ ^[0-9a-fA-F:.]+$ ]] || continue
            # an empty entry caches "no ASN" (e.g. bogons) as well.
            printf '%s\t%s\n' "$asn" "$name" > "$cache_dir/.$addr.$$" && mv -f "$cache_dir/.$addr.$$" "$cache_dir/$addr"
        done
}

for addr in "${addrs[@]}"; do
    [ -f "$cache_dir/$addr" ] || continue
    IFS=$'\t' read -r asn name < "$cache_dir/$addr"
    [ -n "$asn" ] && printf '%s\t%s\t%s\n' "$addr" "$asn" "$name"
done

exit 0
