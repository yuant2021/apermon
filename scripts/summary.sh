#!/usr/bin/env bash
# Prints a human-readable summary of an apermon event. Meant to be called by other scripts (e.g., mailgun, telegram)
# to generate the message body. ASNs are looked up with ipinfo.py when IPINFO_MMDB is set.

cd "`dirname "$0"`"

# fmt_rate <value> <unit>: "2310000000 bps" -> "2.31 Gbps"
fmt_rate() {
    awk -v v="$1" -v u="$2" 'BEGIN {
        if (v >= 1e9) printf "%.2f G%s", v / 1e9, u
        else if (v >= 1e6) printf "%.2f M%s", v / 1e6, u
        else if (v >= 1e3) printf "%.2f k%s", v / 1e3, u
        else printf "%d %s", v, u
    }'
}

# fmt_duration <seconds>: "3725" -> "1h 2m 5s"
fmt_duration() {
    local s="$1" out=''
    [ "$s" -ge 3600 ] && out="$((s / 3600))h "
    [ "$s" -ge 60 ] && out="$out$((s % 3600 / 60))m "
    printf '%s%ds' "$out" "$((s % 60))"
}

row() {
    printf '%-10s%s\n' "$1" "$2"
}

# PREFIX of a net aggregator lists every prefix of the net, which can be thousands for BGP-collected nets.
prefixes() {
    local list=($PREFIX) max=5
    local out="${list[*]:0:max}"
    [ ${#list[@]} -gt $max ] && out="$out (+$((${#list[@]} - max)) more)"
    printf '%s' "$out"
}

header() {
    printf '%s %s %s [%s]\n\n' "$1" "$AGGREGATOR" "$TARGET" "$TRIGGER"

    if [ "$AGGREGATOR" = "net" ]; then
        row 'prefix' "`prefixes`"
    else
        target_asn="`./ipinfo.py "$TARGET" | cut -f2- | tr '\t' ' '`"
        row 'target' "$TARGET${target_asn:+  $target_asn}"
        row 'prefix' "$PREFIX ($NET)"
    fi
}

[ "$TYPE" = "ban" ] && {
    header BAN
    row 'inbound' "`fmt_rate "$IN_BPS" bps`  `fmt_rate "$IN_PPS" pps`"
    row 'outbound' "`fmt_rate "$OUT_BPS" bps`  `fmt_rate "$OUT_PPS" pps`"

    flows="`<<< "$FLOWS" sed 1d | grep -v '^$'`"
    [ -z "$flows" ] && exit 0

    # the remote end of the flows: sources for mostly inbound traffic, destinations otherwise.
    remote_col=4
    remote=source
    remote_label='src addrs'
    [ "${OUT_BPS:-0}" -gt "${IN_BPS:-0}" ] && {
        remote_col=5
        remote=destination
        remote_label='dst addrs'
    }

    # "<category>\t<key>\t<share of sampled bytes in %>"; ports only for tcp/udp, non-first fragments carry none.
    stats="`<<< "$flows" awk -F, -v rc="$remote_col" '
        function proto(p) {
            if (p == 1) return "ICMP"
            if (p == 6) return "TCP"
            if (p == 17) return "UDP"
            if (p == 47) return "GRE"
            if (p == 50) return "ESP"
            if (p == 58) return "ICMPv6"
            return "proto-" p
        }
        {
            b["proto\t" proto($6)] += $9
            if ($11 == 2) {
                b["sport\tfragment"] += $9
                b["dport\tfragment"] += $9
            } else if ($6 == 6 || $6 == 17) {
                b["sport\t" $7] += $9
                b["dport\t" $8] += $9
            }
            b["remote\t" $rc] += $9
            total += $9
        }
        END {
            for (k in b) printf "%s\t%.1f\n", k, (total > 0 ? b[k] * 100 / total : 0)
        }'`"

    # top <category> <n>: "<share>\t<key>" lines, largest first
    top() {
        <<< "$stats" awk -F'\t' -v c="$1" '$1 == c { print $3 "\t" $2 }' | sort -t$'\t' -k1,1nr | head -n "$2"
    }

    # inline <category> <n>: "UDP 92.1%  TCP 7.9%"
    inline() {
        top "$1" "$2" | awk -F'\t' '{ printf "%s%s %s%%", (NR > 1 ? "  " : ""), $2, $1 }'
    }

    printf '\n%d sampled flows, share of bytes:\n' "`<<< "$flows" wc -l`"
    row 'protocol' "`inline proto 4`"
    [ -n "`top sport 1`" ] && {
        row 'src port' "`inline sport 4`"
        row 'dst port' "`inline dport 4`"
    }
    row "$remote_label" "`top remote 1000 | wc -l`"

    # aggregate remote addresses by origin ASN
    remote_asns="`top remote 1000 | cut -f2 | xargs ./ipinfo.py`"
    [ -n "$remote_asns" ] && {
        printf '\ntop %s ASNs:\n' "$remote"
        awk -F'\t' 'NR == FNR { asn[$1] = $2 " " $3; next } $2 in asn { share[asn[$2]] += $1 } END {
            for (a in share) printf "%.1f\t%s\n", share[a], a
        }' <(echo "$remote_asns") <(top remote 1000) | sort -t$'\t' -k1,1nr | head -n 5 | awk -F'\t' '{ printf "%6.1f%%  %s\n", $1, $2 }'
    }
}

[ "$TYPE" = "unban" ] && {
    header UNBAN
    row 'peak in' "`fmt_rate "$PEAK_IN_BPS" bps`  `fmt_rate "$PEAK_IN_PPS" pps`"
    row 'peak out' "`fmt_rate "$PEAK_OUT_BPS" bps`  `fmt_rate "$PEAK_OUT_PPS" pps`"
    row 'first' "`date -d "@$FIRST_TRIGGERED" '+%F %T %Z'`"
    row 'last' "`date -d "@$LAST_TRIGGERED" '+%F %T %Z'`"
    row 'duration' "`fmt_duration $((LAST_TRIGGERED - FIRST_TRIGGERED))`"
}

exit 0
