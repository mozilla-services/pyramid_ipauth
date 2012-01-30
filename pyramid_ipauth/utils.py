# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Utility functions for pyramid_ipauth

"""

import re
import socket

from netaddr import IPAddress, IPNetwork, IPGlob, IPRange, IPSet

#  This is used to split a string on an optional comma,
#  followed by any amount of whitespace.
_COMMA_OR_WHITESPACE = re.compile(r",?\s*")


def get_ip_address(request, proxies=None):
    """Get the originating IP address from the given request.

    This function resolves and returns the originating IP address of the
    given request, by looking up the REMOTE_ADDR and HTTP_X_FORWARDED_FOR
    entries from the request environment.

    By default this function does not make use of the X-Forwarded-For header.
    To use it you must specify a set of trusted proxy IP addresses.  The
    X-Forwarded-For header will then be traversed back through trusted proxies,
    stopping either at the first untrusted proxy or at the claimed original IP.
    """
    if proxies is None:
        proxies = IPSet()
    elif not isinstance(proxies, IPSet):
        proxies = make_ip_set(proxies)
    # Get the chain of proxied IP addresses, most recent proxy last.
    addr_chain = []
    try:
        xff = request.environ["HTTP_X_FORWARDED_FOR"]
    except KeyError:
        pass
    else:
        addr_chain.extend(a.strip() for a in xff.split(","))
    addr_chain.append(request.environ["REMOTE_ADDR"])
    # Pop trusted proxies from the list until we get the original addr,
    # or until we hit a malformed or untrusted proxy.
    addr = IPAddress(addr_chain.pop())
    while addr_chain:
        # If it's not a trusted proxy, stop the chain.
        if addr not in proxies:
            break
        # If next is a malformed IP address, stop the chain.
        if len(addr_chain[-1].split()) > 1:
            break
        addr = IPAddress(addr_chain.pop())
    return addr


def check_ip_address(request, ipaddrs, proxies=None):
    """Check whether a request originated within the given ip address set.

    This function checks whether the originating IP address of the request
    is within the given set of IP addresses, returning True if it is and False
    if not.

    By default this function does not make use of the X-Forwarded-For header.
    To use it you must specify a set of trusted proxy IP addresses which will
    be passed on to the get_ip_address function.
    """
    if not isinstance(ipaddrs, IPSet):
        ipaddrs = make_ip_set(ipaddrs)
    ipaddr = get_ip_address(request, proxies)
    return (ipaddr in ipaddrs)


def make_ip_set(ipaddrs):
    """Parse a variety of IP specifications into an IPSet object.

    This is a convenience function that allows you to specify a set of
    IP addresses in a variety of ways:

        * as an IPSet, IPAddress, IPNetwork, IPGlob or IPRange object
        * as the literal None for the empty set
        * as an int parsable by IPAddress
        * as a string parsable by parse_ip_set
        * as an iterable of IP specifications

    """
    # If it's already an IPSet, well, that's easy.
    if isinstance(ipaddrs, IPSet):
        return ipaddrs
    # None represents the empty set.
    if ipaddrs is None:
        return IPSet()
    # Integers represent a single address.
    if isinstance(ipaddrs, (int, long)):
        return IPSet((IPAddress(ipaddrs),))
    # Strings get parsed as per parse_ip_set
    if isinstance(ipaddrs, basestring):
        return parse_ip_set(ipaddrs)
    # Other netaddr types can be converted into a set.
    if isinstance(ipaddrs, (IPAddress, IPNetwork)):
        return IPSet((ipaddrs,))
    if isinstance(ipaddrs, (IPGlob, IPRange)):
        return IPSet(ipaddrs.cidrs())
    # Anything iterable can be mapped over and unioned.
    try:
        ipspecs = iter(ipaddrs)
    except Exception:
        pass
    else:
        ipset = IPSet()
        for ipspec in ipspecs:
            ipset |= make_ip_set(ipspec)
        return ipset
    # Anything else is an error
    raise ValueError("can't convert to IPSet: %r" % (ipaddrs,))


def parse_ip_set(ipaddrs):
    """Parse a string specification into an IPSet.

    This function takes a string representing a set of IP addresses and
    parses it into an IPSet object.  Acceptable formats for the string
    include:

        * "all":        all possible IPv4 and IPv6 addresses
        * "local":      all local addresses of the machine
        * "A.B.C.D"     a single IP address
        * "A.B.C.D/N"   a network address specification
        * "A.B.C.*"     a glob matching against all possible numbers
        * "A.B.C.D-E"   a glob matching against a range of numbers
        * a whitespace- or comma-separated string of the above

    """
    ipset = IPSet()
    ipaddrs = ipaddrs.lower().strip()
    if not ipaddrs:
        return ipset
    for ipspec in _COMMA_OR_WHITESPACE.split(ipaddrs):
        # The string "local" maps to all local addresses on the machine.
        if ipspec == "local":
            ipset.add(IPNetwork("127.0.0.0/8"))
            for addr in get_local_ip_addresses():
                ipset.add(addr)
        # The string "all" maps to app IPv4 and IPv6 addresses.
        elif ipspec == "all":
            ipset.add(IPNetwork("0.0.0.0/0"))
            ipset.add(IPNetwork("::"))
        # Strings containing a "/" are assumed to be network specs
        elif "/" in ipspec:
            ipset.add(IPNetwork(ipspec))
        # Strings containing a "*" or "-" are assumed to be glob patterns
        elif "*" in ipspec or "-" in ipspec:
            for cidr in IPGlob(ipspec).cidrs():
                ipset.add(cidr)
        # Anything else must be a single address
        else:
            ipset.add(IPAddress(ipspec))
    return ipset


def get_local_ip_addresses():
    """Iterator yielding all local IP addresses on the machine."""
    # XXX: how can we enumerate all interfaces on the machine?
    # I don't really want to shell out to `ifconfig`
    for addr in socket.gethostbyname_ex(socket.gethostname())[2]:
        yield IPAddress(addr)
