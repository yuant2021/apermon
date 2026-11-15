apermon script examples
---

Here are some ready-to-use example scripts that can be added to actions. 

### exabgp.sh

Announce / withdraw blackhole routes with [exabgp](https://github.com/Exa-Networks/exabgp). First [install exabgp 4.x](https://github.com/Exa-Networks/exabgp#installation) and socat. On a debian-based system:

```
# apt install exabgp socat
```

Once installed, configure exabgp with your details. If you installed `exabgp` with a package manager like `apt`, the configuration file is likely `/etc/exabgp/exabgp.conf`. Example configuration:

```
process apermon {
    run /usr/bin/socat stdout pipe:/var/run/exabgp.sock;
    encoder json;
}

neighbor 10.66.66.1 {
    router-id 10.66.66.66;
    local-address 10.66.66.66;
    local-as 65001;
    peer-as 65001;

    api {
        processes [ apermon ];
    }
}
```

Then add the script as a script for your action and set environment variables accordingly:

```
actions {
    my-action {
        script "/path/to/exabgp.sh" {
            events [ ban unban ];
            env {
                EXABGP_CONTROL_SOCKET   = "/var/run/exabgp.sock";
                EXABGP_COMMUNITIES      = "65535:666 65001:666";
                EXABGP_NEXTHOP          = "10.66.66.66";
                LOCKFILE                = "/tmp/apermon-exabgp.lock";
            }
        }
        ...
    }
    ...
}
```

The variables should be self-explanatory. Note that: 

- `EXABGP_CONTROL_SOCKET` should be the named pipe you created with socat in your exabgp configuration. You should configure proper permissions so this file is writeable by `apermon`.
- `LOCKFILE` can be any file that's writable by `apermon`. 

#### origin ASN prepend

Upstream blackhole sessions often only accept a route when its AS path ends in the AS that originates the prefix (e.g., your customer's AS). `exabgp.sh` can look up the origin ASN of every blackholed target with [ipinfo.sh](#ipinfosh) and prepend it to the announced AS path:

```
env {
    ...
    EXABGP_PREPEND_ORIGIN_ASN   = "1";
    EXABGP_PREPEND_SKIP_ASNS    = "65001";
    IPINFO_TOKEN                = "...";
}
```

- `EXABGP_PREPEND_ORIGIN_ASN=1` turns the lookup on. Announcements become `announce route 192.0.2.1/32 ... as-path [ 64500 ]`.
- `EXABGP_PREPEND_SKIP_ASNS` lists origin ASNs that are announced without the prepend. Put your own ASN here: a router drops routes whose AS path contains its own AS.
- If the lookup fails or the target has no origin ASN, the route is announced without the prepend.
- `ipinfo.sh` must be kept in the same directory with `exabgp.sh`.

### ipinfo.sh

Looks up the origin ASN of addresses with the [IPinfo Lite API](https://ipinfo.io/developers/lite-api) (free, unlimited; [get a token](https://ipinfo.io/signup)). Used by `summary.sh` and `exabgp.sh`; it needs `curl` and `jq`. Lookups are disabled when `IPINFO_TOKEN` is not set. Environment variables:

- `IPINFO_TOKEN`: IPinfo access token.
- `IPINFO_CACHE_DIR`: cache directory, default `${TMPDIR:-/tmp}/apermon-ipinfo`. Must be writable by `apermon`.
- `IPINFO_CACHE_TTL`: cache lifetime in seconds, default `86400`.
- `IPINFO_TIMEOUT`: API timeout in seconds, default `5`.

```
$ IPINFO_TOKEN=... ./ipinfo.sh 8.8.8.8 1.1.1.1
8.8.8.8	AS15169	Google LLC
1.1.1.1	AS13335	Cloudflare, Inc.
```

### summary.sh

Prints summary of the event when called. It's meant to be called by other scripts (e.g., mailgun, telegram) to generate the message body. Instead of listing flows, it breaks the sampled flows down by protocol, ports, and origin ASN of the remote addresses (sources for mostly inbound traffic, destinations otherwise):

```
BAN host 192.0.2.5 [protect-my-network]

target    192.0.2.5  AS64500 Example Networks
prefix    192.0.2.0/24 (my-network)
inbound   2.31 Gbps  1.20 Mpps
outbound  12.40 Mbps  3.10 kpps

100 sampled flows, share of bytes:
protocol  UDP 99.4%  TCP 0.6%
src port  123 79.9%  53 13.3%  fragment 6.2%  50001 0.1%
dst port  fragment 6.2%  40001 1.3%  40002 1.3%  40003 1.3%
src addrs 38

top source ASNs:
  86.2%  AS64501 Reflector Networks
  13.2%  AS64502 Other Networks
```

ASNs are only shown when `IPINFO_TOKEN` is set (see [ipinfo.sh](#ipinfosh)); set it in the `env` of the script that calls `summary.sh`.

### mailgun.sh

Sends email with mailgun. Add the script as a script for your action and set environment variables accordingly:

```
actions {
    my-action {
        script "/path/to/mailgun.sh" {
            event [ ban unban ];
            env {
                API_KEY = "api:key-...";
                DOMAIN  = "noreply.example.com";
                FROM    = "AperMon <apermon@noreply.example.com>";
                TO      = "noc@example.com";
                SUBJECT = "[apermon] $TRIGGER: $TYPE $TARGET";
            }
        }
        ...
    }
    ...
}
```

Note that:

- The script must be kept in the same directory with `summary.sh` and `ipinfo.sh` scripts.
- `SUBJECT` env will be `eval` by the script (i.e., `eval echo "$SUBJECT"`) to expand the variables.

### telegram.sh

Sends message to [Telegram](https://telegram.org) chat with [Telegram bot API](https://core.telegram.org/bots). Add the script as a script for your action and set environment variables accordingly:

```
actions {
    my-action {
        script "/path/to/telegram.sh" {
            event [ ban unban ];
            env {
                BOT_TOKEN = "...";
                CHAT_ID   = "...";
            }
        }
        ...
    }
    ...
}
```

The summary is sent as an HTML `<pre>` block so its columns stay aligned. Note that the script must be kept in the same directory with `summary.sh` and `ipinfo.sh` scripts.
