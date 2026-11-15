#include <errno.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "telegraf.h"
#include "context.h"
#include "log.h"

// keep datagrams below a typical MTU so they aren't fragmented on the way to a remote telegraf.
#define TELEGRAF_DATAGRAM_SIZE 1400
#define TELEGRAF_LINE_SIZE 512

static const apermon_config *_config;
static int _fd = -1;
static time_t _last_dump;

static char _buf[TELEGRAF_DATAGRAM_SIZE];
static size_t _len;
static unsigned _n_failed;
static int _last_errno;

static uint64_t timestamp_ns(const struct timeval *tv) {
    return (uint64_t) tv->tv_sec * 1000000000 + (uint64_t) tv->tv_usec * 1000;
}

static void flush() {
    if (_len == 0) {
        return;
    }

    // non-blocking: a datagram that doesn't fit in the socket buffer is dropped instead of stalling sflow processing.
    if (sendto(_fd, _buf, _len, 0, _config->telegraf_addr->ai_addr, _config->telegraf_addr->ai_addrlen) < 0) {
        ++_n_failed;
        _last_errno = errno;
    }

    _len = 0;
}

static void report_failures() {
    if (_n_failed > 0) {
        log_warn("failed to send %u telegraf datagram(s): %s\n", _n_failed, strerror(_last_errno));
        _n_failed = 0;
    }
}

// len: snprintf() result for line
static void emit(const char *line, int len) {
    if (len < 0 || len >= TELEGRAF_LINE_SIZE) {
        log_warn("internal error: telegraf line too long, dropped.\n");
        return;
    }

    if (_len + len > sizeof(_buf)) {
        flush();
    }

    memcpy(_buf + _len, line, len);
    _len += len;
}

// line protocol tags, sorted by key. trigger and net names are config identifiers ([a-zA-Z][a-zA-Z0-9_-]*) and
// targets are addresses or prefixes, so no tag value needs escaping.
static void format_tags(char *buf, size_t len, const char *trigger, uint8_t aggregator, uint32_t af, const void *key, const apermon_config_prefix_lists *net, const apermon_prefix *pfx) {
    char addr[INET6_ADDRSTRLEN + 1], prefix[INET6_ADDRSTRLEN + 1];

    if (aggregator == APERMON_AGGREGATOR_NET) {
        snprintf(buf, len, "aggregator=net,net=%s,target=%s,trigger=%s", net->name, net->name, trigger);
        return;
    }

    inet_ntop(af == SFLOW_AF_INET ? AF_INET : AF_INET6, key, addr, sizeof(addr));

    if (aggregator == APERMON_AGGREGATOR_PREFIX) {
        snprintf(buf, len, "aggregator=prefix,net=%s,target=%s/%u,trigger=%s", net->name, addr, pfx->cidr, trigger);
        return;
    }

    if (pfx->af == SFLOW_AF_INET) {
        inet_ntop(AF_INET, &pfx->inet, prefix, sizeof(prefix));
    } else {
        inet_ntop(AF_INET6, pfx->inet6, prefix, sizeof(prefix));
    }

    snprintf(buf, len, "aggregator=host,net=%s,prefix=%s/%u,target=%s,trigger=%s", net->name, prefix, pfx->cidr, addr, trigger);
}

int init_telegraf(const apermon_config *config) {
    const struct addrinfo *ai = config->telegraf_addr;
    char host[NI_MAXHOST], port[NI_MAXSERV];

    _config = config;
    _last_dump = time(NULL);

    if (ai == NULL) {
        return 0;
    }

    // trigger scripts are forked from this process; don't leak the socket to them.
    _fd = socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, ai->ai_protocol);
    if (_fd < 0) {
        log_fatal("socket(): %s\n", strerror(errno));
        return -1;
    }

    if (getnameinfo(ai->ai_addr, ai->ai_addrlen, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
        log_info("sending telegraf metrics to %s port %s every %u second(s).\n", host, port, config->telegraf_dump_interval);
    }

    return 0;
}

void telegraf_timed_callback(const struct timeval *now) {
    const apermon_config_triggers *t;
    const apermon_hash_item *item;
    const apermon_aggregated_flow *af;
    const apermon_trigger_state *ts;
    char tags[TELEGRAF_LINE_SIZE], line[TELEGRAF_LINE_SIZE];
    size_t n_targets, n_banned;
    uint64_t timestamp = timestamp_ns(now);

    if (_fd < 0 || now->tv_sec - _last_dump < _config->telegraf_dump_interval) {
        return;
    }

    _last_dump = now->tv_sec;

    for (t = _config->triggers; t != NULL; t = t->next) {
        n_targets = n_banned = 0;

        for (item = t->ctx->aggr_hash->head; item != NULL; item = item->iter_next) {
            af = (const apermon_aggregated_flow *) item->value;

            // same window as the status file: rates of targets without recent samples are stale.
            if (now->tv_sec - af->last_modified > FLOW_DUMP_BACKTRACK) {
                continue;
            }

            ++n_targets;
            format_tags(tags, sizeof(tags), t->name, af->aggregator, af->flow_af, &af->inet, af->prefix_list, af->prefix);
            emit(line, snprintf(line, sizeof(line), "apermon_traffic,%s in_bps=%lui,out_bps=%lui,in_pps=%lui,out_pps=%lui %lu\n",
                tags, af->in_bps, af->out_bps, af->in_pps, af->out_pps, timestamp
            ));
        }

        for (item = t->ctx->trigger_status->head; item != NULL; item = item->iter_next) {
            ts = (const apermon_trigger_state *) item->value;

            if (ts->flags & APERMON_TRIGGER_FLAG_FIRED) {
                ++n_banned;
            }
        }

        emit(line, snprintf(line, sizeof(line), "apermon_trigger,trigger=%s targets=%zui,banned=%zui %lu\n", t->name, n_targets, n_banned, timestamp));
    }

    flush();
    report_failures();
}

void telegraf_ban(const apermon_config_triggers *trigger, const apermon_aggregated_flow *flow) {
    char tags[TELEGRAF_LINE_SIZE], line[TELEGRAF_LINE_SIZE];

    if (_fd < 0) {
        return;
    }

    format_tags(tags, sizeof(tags), trigger->name, flow->aggregator, flow->flow_af, &flow->inet, flow->prefix_list, flow->prefix);
    emit(line, snprintf(line, sizeof(line), "apermon_event,%s,type=ban in_bps=%lui,out_bps=%lui,in_pps=%lui,out_pps=%lui %lu\n",
        tags, flow->in_bps, flow->out_bps, flow->in_pps, flow->out_pps, timestamp_ns(&trigger->ctx->now)
    ));

    flush();
    report_failures();
}

void telegraf_unban(const apermon_trigger_state *ts) {
    const apermon_config_triggers *trigger = ts->trigger;
    char tags[TELEGRAF_LINE_SIZE], line[TELEGRAF_LINE_SIZE];

    if (_fd < 0) {
        return;
    }

    format_tags(tags, sizeof(tags), trigger->name, ts->aggregator, ts->af, &ts->inet, ts->prefix_list, ts->prefix);
    emit(line, snprintf(line, sizeof(line), "apermon_event,%s,type=unban peak_in_bps=%lui,peak_out_bps=%lui,peak_in_pps=%lui,peak_out_pps=%lui,duration=%lui %lu\n",
        tags, ts->peak_in_bps, ts->peak_out_bps, ts->peak_in_pps, ts->peak_out_pps, (uint64_t) (ts->last_triggered - ts->first_triggered),
        timestamp_ns(&trigger->ctx->now)
    ));

    flush();
    report_failures();
}
