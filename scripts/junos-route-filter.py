#!/usr/bin/env python3
"""Add banned prefixes to a Junos route-filter-list over NETCONF.

Run as an apermon `ban` script. Every banned prefix (the PREFIX env) becomes

    set policy-options route-filter-list <JUNOS_ROUTE_FILTER_LIST> <prefix> [<JUNOS_MATCH_TYPE>]

Entries are only ever added; `unban` events are ignored.

apermon runs one script per event, concurrently. Committing from each of them races on the Junos candidate
configuration ("configuration database locked", "commit in progress"). Instead, every run appends its prefixes to a
spool file and then waits for the commit lock. Whoever holds the lock commits everything spooled so far in a single
commit, so a burst of events ends up in one or two commits. A run that finds the spool empty exits: an earlier holder
already committed its prefixes. On the device, the candidate configuration is locked for the load and commit, and
lock/commit failures (e.g., another user editing or committing) are retried with backoff until
JUNOS_COMMIT_DEADLINE. Prefixes that still fail to commit go back to the spool and are retried by the next event.

Requires ncclient (`pip install ncclient`).
"""

import fcntl
import ipaddress
import os
import sys
import time

try:
    from ncclient import manager
    from ncclient.operations import RaiseMode
except ImportError:
    raise SystemExit('junos-route-filter: error: ncclient not found, install it with "pip install ncclient"')


def log(msg):
    print(f'junos-route-filter: {msg}', file=sys.stderr, flush=True)


def env(name, default=None):
    value = os.environ.get(name) or default
    if value is None:
        raise SystemExit(f'junos-route-filter: error: missing env {name}')
    return value


class Config:
    def __init__(self):
        self.host = env('NETCONF_HOST')
        self.port = int(env('NETCONF_PORT', '830'))
        self.username = env('NETCONF_USERNAME')
        self.password = os.environ.get('NETCONF_PASSWORD') or None
        self.key_file = os.environ.get('NETCONF_KEY_FILE') or None
        self.hostkey_verify = env('NETCONF_HOSTKEY_VERIFY', '1') != '0'
        self.timeout = int(env('NETCONF_TIMEOUT', '120'))
        self.route_filter_list = env('JUNOS_ROUTE_FILTER_LIST')
        self.match_type = os.environ.get('JUNOS_MATCH_TYPE', '')
        self.spool_dir = env('JUNOS_SPOOL_DIR')
        self.commit_deadline = int(env('JUNOS_COMMIT_DEADLINE', '300'))

        if self.password is None and self.key_file is None:
            raise SystemExit('junos-route-filter: error: missing env NETCONF_PASSWORD or NETCONF_KEY_FILE')


class Spool:
    """Prefixes waiting to be committed, one per line, shared by all runs."""

    def __init__(self, directory):
        os.makedirs(directory, exist_ok=True)
        self.path = os.path.join(directory, 'pending')
        self.commit_lock = os.path.join(directory, 'commit.lock')

    def add(self, prefixes):
        with open(self.path, 'a') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(''.join(f'{p}\n' for p in prefixes))

    def take(self):
        with open(self.path, 'a+') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.seek(0)
            prefixes = {line.strip() for line in f if line.strip()}
            f.truncate(0)
        return prefixes


def banned_prefixes():
    """PREFIX holds one prefix for host/prefix aggregators and every prefix of the net for net aggregators."""
    return {str(ipaddress.ip_network(p, strict=False)) for p in os.environ.get('PREFIX', '').split()}


def sort_key(prefix):
    net = ipaddress.ip_network(prefix)
    return net.version, net


def push(cfg, prefixes):
    """Load and commit `prefixes` in one exclusive edit of the candidate configuration."""
    rfl = cfg.route_filter_list
    commands = [f'set policy-options route-filter-list {rfl} {p} {cfg.match_type}'.rstrip() for p in prefixes]

    with manager.connect(
        host=cfg.host,
        port=cfg.port,
        username=cfg.username,
        password=cfg.password,
        key_filename=cfg.key_file,
        look_for_keys=False,
        allow_agent=False,
        hostkey_verify=cfg.hostkey_verify,
        device_params={'name': 'junos'},
        timeout=cfg.timeout,
    ) as m:
        # Junos reports harmless warnings as rpc-errors; only fail on real errors.
        m.raise_mode = RaiseMode.ERRORS

        # fails while another session holds the lock or has uncommitted changes; the caller retries.
        m.lock('candidate')
        try:
            m.load_configuration(action='set', config=commands)
            m.commit(comment=f'apermon {os.environ.get("TRIGGER", "")}: add {len(prefixes)} prefix(es) to {rfl}')
        except BaseException:
            try:
                m.discard_changes()
            except Exception as e:
                log(f'discard-changes failed: {e}')
            raise
        finally:
            m.unlock('candidate')


def commit_spooled(cfg, spool):
    """Commit everything in the spool; caller holds the commit lock. Returns False if prefixes were left behind."""
    deadline = time.monotonic() + cfg.commit_deadline
    pending = spool.take()
    delay = 1

    while pending:
        prefixes = sorted(pending, key=sort_key)
        try:
            push(cfg, prefixes)
        except Exception as e:
            if time.monotonic() + delay > deadline:
                log(f'giving up, prefixes kept for the next event: {e}')
                spool.add(pending)
                return False

            log(f'commit failed, retrying in {delay}s: {e}')
            time.sleep(delay)
            delay = min(delay * 2, 30)
            # pick up prefixes spooled by other events in the meantime.
            pending |= spool.take()
            continue

        log(f'committed {" ".join(prefixes)}')
        pending = set()

    return True


def main():
    if os.environ.get('TYPE') != 'ban':
        return 0

    cfg = Config()
    prefixes = banned_prefixes()
    if not prefixes:
        log('error: missing PREFIX')
        return 1

    spool = Spool(cfg.spool_dir)
    spool.add(prefixes)

    with open(spool.commit_lock, 'a') as lock:
        # blocks while another run commits; that run may commit our prefixes too.
        fcntl.flock(lock, fcntl.LOCK_EX)
        return 0 if commit_spooled(cfg, spool) else 1


if __name__ == '__main__':
    sys.exit(main())
