==============
pyramid_ipauth
==============

An authentication policy for Pyramid that sets identity and effective
principals based on the remote IP address of the request.


Overview
========

To perform IP-address-based authentication, create an IPAuthenticationPolicy
and specify the target IP range, userid and effective principals.  Then set it
as the authentication policy in your configurator::

    authn_policy = IPAuthenticationPolicy("127.0.*.*", "myuser", ["locals"])
    config.set_authentication_policy(authn_policy)

This will cause all requests from IP addresses in the 127.0.*.* range to be
authenticated as user "myuser" and have the effective principal "locals".

It is also possible to specify the configuration options in your deployment
file::

    [app:pyramidapp]
    use = egg:mypyramidapp

    ipauth.ipaddrs = 127.0.0.* 127.0.1.*
    ipauth.principals = locals

You can then simply include the pyramid_ipauth package into your configurator::

    config.include("pyramid_ipauth")

It will detect the ipauth settings and construct and appopriate policy.

Note that this package only supports matching against a single set of IP
addresss.  If you need to assign different credentials to different sets
of IP addresses, you can use the pyramid_multiauth package in conjunction
with pyramid_ipauth:

    http://github.com/mozilla-services/pyramid_multiauth


Specifying IP Addresses
=======================

IP addresses can be specified in a variety of forms, including:

    * "all":        all possible IPv4 and IPv6 addresses
    * "local":      all local addresses of the machine
    * "A.B.C.D"     a single IP address
    * "A.B.C.D/N"   a network address specification
    * "A.B.C.*"     a glob matching against all possible numbers
    * "A.B.C.D-E"   a glob matching against a range of numbers
    * a whitespace- or comma-separated string of any of the above
    * a netaddr IPAddress, IPRange, IPGlob, IPNetork of IPSet object
    * a list, tuple or iterable of any of the above


Proxies
=======

This module does not respect the X-Forwarded-For header by default, since it
can be spoofed easily by malicious clients.  If your server is behind a 
trusted proxy that sets the X-Forwarded-For header, you should explicitly
declare the set of trusted proxies like so::

    IPAuthenticationPolicy("127.0.*.*",
                           principals=["local"],
                           proxies = "127.0.0.1")

The set of trusted proxy addresses can be specified using the same syntax as
the set of IP addresses to authenticate.
