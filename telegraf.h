#ifndef APERMON_TELEGRAF_H
#define APERMON_TELEGRAF_H
#include <sys/time.h>
#include "config.h"
#include "flow.h"
#include "trigger.h"

/* sends metrics and ban/unban events as influxdb line protocol over udp (e.g. to telegraf's socket_listener) */

int init_telegraf(const apermon_config *config);
void telegraf_timed_callback(const struct timeval *now);
void telegraf_ban(const apermon_config_triggers *trigger, const apermon_aggregated_flow *flow);
void telegraf_unban(const apermon_trigger_state *ts);

#endif // APERMON_TELEGRAF_H
