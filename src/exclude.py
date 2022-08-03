from bisect import bisect
from ipaddress import IPv4Address, IPv4Network

import random

_EXCLUDE_NETS = [
    # "This" network
    '0.0.0.0/8',
    # Private networks
    '10.0.0.0/8',
    # Carrier-grade NAT - RFC 6598',
    '100.64.0.0/10',
    # Host loopback
    '127.0.0.0/8',
    # Link local
    '169.254.0.0/16',
    # Private networks'
    '172.16.0.0/12',
    # IETF Protocol Assignments
    '192.0.0.0/24',
    # DS-Lite
    '192.0.0.0/29',
    # NAT64
    '192.0.0.170/32',
    # DNS64
    '192.0.0.171/32',
    # Documentation (TEST-NET-1)
    '192.0.2.0/24',
    # 6to4 Relay Anycast
    '192.88.99.0/24',
    # Private networks
    '192.168.0.0/16',
    # Benchmarking
    '198.18.0.0/15',
    # Documentation (TEST-NET-2)
    '198.51.100.0/24',
    # Documentation (TEST-NET-3)
    '203.0.113.0/24',
    # Reserved
    '240.0.0.0/4',
    # Limited Broadcast
    '255.255.255.255/32',
    # DNS providers
    '1.1.1.1/32',
    '1.0.0.1/32',
    '8.8.8.8/32',
    '8.8.4.4/32',
    '208.67.222.222/32',
    '208.67.220.220/32',
    # Cloudflare
    '173.245.48.0/20',
    '103.21.244.0/22',
    '103.22.200.0/22',
    '103.31.4.0/22',
    '141.101.64.0/18',
    '108.162.192.0/18',
    '190.93.240.0/20',
    '188.114.96.0/20',
    '197.234.240.0/22',
    '198.41.128.0/17',
    '162.158.0.0/15',
    '104.16.0.0/13',
    '104.24.0.0/14',
    '172.64.0.0/13',
    '131.0.72.0/22',
    # DDoS-Guard
    '185.129.100.0/22',
    '185.178.208.0/22',
    '91.215.40.0/22',
    '45.10.240.0/22',
    # StormWall
    '185.71.64.0/22',
    '185.121.240.0/22',
]

BYPASS_GATES = [
    '94.79.19.34:80',
    '94.79.19.48:80',
    '94.79.19.47:80',
    '94.79.19.34:80',
    '185.86.148.106:80',
]

def _get_exclude_nets():
    for net in _EXCLUDE_NETS:
        net = IPv4Network(net)
        yield (
            (int(net.network_address), int(net.broadcast_address))
        )


def _reduce(ranges):
    ranges.sort()
    new_ranges = []
    left, right = ranges[0]
    for rng in ranges[1:]:
        next_left, next_right = rng
        if right + 1 < next_left:  # Is the next range to the right?
            new_ranges.append((left, right))  # Close the current range.
            left, right = rng  # Start a new range.
        else:
            right = max(right, next_right)  # Extend the current range.
    new_ranges.append((left, right))  # Close the last range.
    return new_ranges


_EXCLUDES = _reduce(list(_get_exclude_nets()))
# For binary search
_EXCLUDE_STARTS = [ex[0] for ex in _EXCLUDES]


def is_forbidden_ip(ip: str):
    ip = int(IPv4Address(ip))
    range_idx = bisect(_EXCLUDE_STARTS, ip) - 1
    exclude_range = _EXCLUDES[range_idx]
    return exclude_range[0] <= ip <= exclude_range[1]

def get_bypass():
    return random.choice(BYPASS_GATES)
