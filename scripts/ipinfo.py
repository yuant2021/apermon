#!/usr/bin/env python3
"""Look up the origin ASN of IP addresses in a local IPinfo Lite MMDB database.

usage: ipinfo.py <address> [<address> ...]

Prints "<address>\t<asn>\t<as-name>" (e.g. "8.8.8.8	AS15169	Google LLC") for every address with a known ASN.
Prints nothing when IPINFO_MMDB is unset, so callers can treat lookups as optional.

env:
  IPINFO_MMDB  path of ipinfo_lite.mmdb, see https://ipinfo.io/developers/ipinfo-lite-database

Requires the maxminddb module (`pip install maxminddb`).
"""

import os
import sys


def error(msg):
    print(f'ipinfo.py: error: {msg}', file=sys.stderr)
    return 1


def main():
    path = os.environ.get('IPINFO_MMDB')
    if not path:
        return 0

    try:
        import maxminddb
    except ImportError:
        return error('maxminddb not found, install it with "pip install maxminddb"')

    try:
        reader = maxminddb.open_database(path)
    except (OSError, maxminddb.InvalidDatabaseError) as e:
        return error(f'{path}: {e}')

    with reader:
        for addr in sys.argv[1:]:
            try:
                record = reader.get(addr)
            except ValueError:
                # not an inet/inet6 address
                continue

            # Lite records without an ASN only carry the country
            if record and record.get('asn'):
                print(f'{addr}\t{record["asn"]}\t{record.get("as_name", "")}')

    return 0


if __name__ == '__main__':
    sys.exit(main())
