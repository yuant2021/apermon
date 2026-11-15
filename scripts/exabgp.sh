#!/usr/bin/env bash

[[ -z "$EXABGP_CONTROL_SOCKET" || -z "$EXABGP_COMMUNITIES" || -z "$EXABGP_NEXTHOP" || -z "$LOCKFILE" ]] && {
    echo 'error: missing env'
    exit 1
}

EXABGP_ANNOUNCE_TEMPLATE="announce route %s next-hop $EXABGP_NEXTHOP community [ $EXABGP_COMMUNITIES ]%s\n"
EXABGP_WITHDRAW_TEMPLATE="withdraw route %s next-hop $EXABGP_NEXTHOP\n"

[ ! -p "$EXABGP_CONTROL_SOCKET" ] && {
    echo 'error: exabgp control socket not found.'
    exit 1
}

[ ! -w "$EXABGP_CONTROL_SOCKET" ] && {
    echo 'error: exabgp control socket not writable.'
    exit 1
}

[ "$AGGREGATOR" = "net" ] && targets="$PREFIX"
[ "$AGGREGATOR" = "prefix" ] && targets="$PREFIX"
[ "$AGGREGATOR" = "host" ] && {
    targets="$TARGET"
    [ "$AF" = "1" ] && targets="$targets/32"
    [ "$AF" = "2" ] && targets="$targets/128"
}

[ -z "$targets" ] && {
    echo 'error: missing target(s)'
    exit 1
}

# origin ASN of each target ("<address>\t<asn>\t<as-name>"), looked up before taking the lock.
[ "$TYPE" = "ban" ] && [ "$EXABGP_PREPEND_ORIGIN_ASN" = "1" ] && {
    addrs=()
    for target in $targets; do
        addrs+=("${target%/*}")
    done

    ipinfo="`dirname "$0"`/ipinfo.py"
    origins="`"$ipinfo" "${addrs[@]}"`"
}

# as_path <target>: " as-path [ <origin-asn> ]", or nothing if the origin is unknown or listed in EXABGP_PREPEND_SKIP_ASNS.
as_path() {
    local addr="${1%/*}" asn name

    IFS=$'\t' read -r _ asn name <<< "`<<< "$origins" awk -F'\t' -v a="$addr" '$1 == a'`"
    asn="${asn#AS}"
    [ -z "$asn" ] && return

    for skip in $EXABGP_PREPEND_SKIP_ASNS; do
        [ "${skip#AS}" = "$asn" ] && return
    done

    printf ' as-path [ %s ]' "$asn"
    echo "exabgp.sh: prepending AS$asn ($name) to $1" >&2
}

{
    flock 200
    for target in $targets; do {
        [ "$TYPE" = "ban" ] && printf "$EXABGP_ANNOUNCE_TEMPLATE" "$target" "`as_path "$target"`" > "$EXABGP_CONTROL_SOCKET"
        [ "$TYPE" = "unban" ] && printf "$EXABGP_WITHDRAW_TEMPLATE" "$target" > "$EXABGP_CONTROL_SOCKET"
    }; done

} 200> "$LOCKFILE"
