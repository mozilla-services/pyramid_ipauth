# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest2

from netaddr import IPAddress, IPSet, IPRange, IPGlob, IPNetwork

import pyramid.testing
from pyramid.testing import DummyRequest
from pyramid.security import Everyone, Authenticated
from pyramid.interfaces import IAuthenticationPolicy

from pyramid_ipauth import IPAuthenticationPolicy, includeme
from pyramid_ipauth.utils import make_ip_set, get_ip_address, check_ip_address


class IPAuthPolicyTests(unittest2.TestCase):

    def setUp(self):
        self.config = pyramid.testing.setUp()

    def tearDown(self):
        pyramid.testing.tearDown()

    def test_remember_forget(self):
        policy = IPAuthenticationPolicy(["123.123.0.0/16"], "user")
        request = DummyRequest(environ={"REMOTE_ADDR": "192.168.0.1"})
        self.assertEquals(policy.remember(request, "user"), [])
        self.assertEquals(policy.forget(request), [])

    def test_remote_addr(self):
        policy = IPAuthenticationPolicy(["123.123.0.0/16"], "user")
        # Addresses outside the range don't authenticate
        request = DummyRequest(environ={"REMOTE_ADDR": "192.168.0.1"})
        self.assertEquals(policy.authenticated_userid(request), None)
        # Addresses inside the range do authenticate
        request = DummyRequest(environ={"REMOTE_ADDR": "123.123.0.1"})
        self.assertEquals(policy.authenticated_userid(request), "user")
        request = DummyRequest(environ={"REMOTE_ADDR": "123.123.1.2"})
        self.assertEquals(policy.authenticated_userid(request), "user")

    def test_noncontiguous_ranges(self):
        policy = IPAuthenticationPolicy(["123.123.0.0/16", "124.124.1.0/24"],
                                        "user")
        # Addresses outside the range don't authenticate
        request = DummyRequest(environ={"REMOTE_ADDR": "192.168.0.1"})
        self.assertEquals(policy.authenticated_userid(request), None)
        request = DummyRequest(environ={"REMOTE_ADDR": "124.124.0.1"})
        self.assertEquals(policy.authenticated_userid(request), None)
        # Addresses inside the range do authenticate
        request = DummyRequest(environ={"REMOTE_ADDR": "123.123.0.1"})
        self.assertEquals(policy.authenticated_userid(request), "user")
        request = DummyRequest(environ={"REMOTE_ADDR": "124.124.1.2"})
        self.assertEquals(policy.authenticated_userid(request), "user")

    def test_get_ip_address(self):
        # Testing without X-Forwarded-For
        request = DummyRequest(environ={"REMOTE_ADDR": "192.168.0.1"})
        self.assertEquals(get_ip_address(request),
                          IPAddress("192.168.0.1"))
        # Testing with X-Forwaded-For and no trusted proxies
        request = DummyRequest(environ={"REMOTE_ADDR": "192.168.0.1",
                               "HTTP_X_FORWARDED_FOR": "123.123.0.1"})
        self.assertEquals(get_ip_address(request),
                          IPAddress("192.168.0.1"))
        # Testing with an untrusted proxy
        self.assertEquals(get_ip_address(request, "192.168.1.1"),
                          IPAddress("192.168.0.1"))
        # Testing with a trusted proxy
        self.assertEquals(get_ip_address(request, "192.168.0.1"),
                          IPAddress("123.123.0.1"))
        # Testing with a malformed XFF header
        request = DummyRequest(environ={"REMOTE_ADDR": "192.168.0.1",
                           "HTTP_X_FORWARDED_FOR": "124.124.0.1 123.123.0.1"})
        self.assertEquals(get_ip_address(request, "192.168.0.1"),
                          IPAddress("192.168.0.1"))
        # Testing with a trusted proxy and untrusted proxy
        request = DummyRequest(environ={"REMOTE_ADDR": "192.168.0.1",
                           "HTTP_X_FORWARDED_FOR": "124.124.0.1, 123.123.0.1"})
        self.assertEquals(get_ip_address(request, "192.168.0.1"),
                          IPAddress("123.123.0.1"))
        # Testing with several trusted proxies
        request = DummyRequest(environ={"REMOTE_ADDR": "192.168.0.1",
                           "HTTP_X_FORWARDED_FOR": "124.124.0.1, 123.123.0.1"})
        self.assertEquals(get_ip_address(request, "192.168.0.1 123.123.0.1"),
                          IPAddress("124.124.0.1"))

    def test_check_ip_address(self):
        # Testing without X-Forwarded-For
        request = DummyRequest(environ={"REMOTE_ADDR": "192.168.0.1"})
        self.assertTrue(check_ip_address(request, "192.168.0.1"))
        self.assertTrue(check_ip_address(request, "192.168.0.1/8"))
        self.assertFalse(check_ip_address(request, "192.168.0.2"))

    def test_x_forwarded_for(self):
        policy = IPAuthenticationPolicy(["123.123.0.0/16"], "user",
                              proxies=["124.124.0.0/24"])
        # Requests without X-Forwarded-For work as normal
        request = DummyRequest(environ={"REMOTE_ADDR": "192.168.0.1"})
        self.assertEquals(policy.authenticated_userid(request), None)
        request = DummyRequest(environ={"REMOTE_ADDR": "123.123.0.1"})
        self.assertEquals(policy.authenticated_userid(request), "user")
        # Requests with untrusted X-Forwarded-For don't authenticate
        request = DummyRequest(environ={"REMOTE_ADDR": "192.168.0.1",
                               "HTTP_X_FORWARDED_FOR": "123.123.0.1"})
        self.assertEquals(policy.authenticated_userid(request), None)
        # Requests from single trusted proxy do authenticate
        request = DummyRequest(environ={"REMOTE_ADDR": "124.124.0.1",
                               "HTTP_X_FORWARDED_FOR": "123.123.0.1"})
        self.assertEquals(policy.authenticated_userid(request), "user")
        # Requests from chain of trusted proxies do authenticate
        request = DummyRequest(environ={"REMOTE_ADDR": "124.124.0.2",
                          "HTTP_X_FORWARDED_FOR": "123.123.0.1, 124.124.0.1"})
        self.assertEquals(policy.authenticated_userid(request), "user")
        # Requests with untrusted proxy in chain don't authenticate
        request = DummyRequest(environ={"REMOTE_ADDR": "124.124.0.1",
                          "HTTP_X_FORWARDED_FOR": "123.123.0.1, 192.168.0.1"})
        self.assertEquals(policy.authenticated_userid(request), None)

    def test_principals(self):
        policy = IPAuthenticationPolicy(["123.123.0.0/16"],
                                        principals=["test"])
        # Addresses outside the range don't get metadata set
        request = DummyRequest(environ={"REMOTE_ADDR": "192.168.0.1"})
        self.assertEquals(policy.effective_principals(request), [Everyone])
        # Addresses inside the range do get metadata set
        request = DummyRequest(environ={"REMOTE_ADDR": "123.123.0.1"})
        self.assertEquals(policy.effective_principals(request),
                          [Everyone, Authenticated, "test"])
        policy.userid = "user"
        self.assertEquals(policy.effective_principals(request),
                          ["user", Everyone, Authenticated, "test"])

    def test_make_ip_set(self):
        def is_in(ipaddr, ipset):
            ipset = make_ip_set(ipset)
            return IPAddress(ipaddr) in ipset
        #  Test individual IPs
        self.assertTrue(is_in("127.0.0.1", "127.0.0.1"))
        self.assertFalse(is_in("127.0.0.2", "127.0.0.1"))
        #  Test globbing
        self.assertTrue(is_in("127.0.0.1", "127.0.0.*"))
        self.assertTrue(is_in("127.0.1.2", "127.0.*.*"))
        self.assertTrue(is_in("127.0.0.1", "127.0.0.*"))
        self.assertFalse(is_in("127.0.1.2", "127.0.0.*"))
        self.assertTrue(is_in("127.0.0.1", "127.0.0.1-5"))
        self.assertTrue(is_in("127.0.0.5", "127.0.0.1-5"))
        self.assertFalse(is_in("127.0.0.6", "127.0.0.1-5"))
        #  Test networks
        self.assertTrue(is_in("127.0.0.1", "127.0.0.0/8"))
        self.assertTrue(is_in("127.0.0.1", "127.0.0.0/16"))
        self.assertTrue(is_in("127.0.0.1", "127.0.0.0/24"))
        self.assertFalse(is_in("127.0.1.2", "127.0.0.0/24"))
        #  Test literal None
        self.assertFalse(is_in("127.0.0.1", None))
        #  Test special strings
        self.assertTrue(is_in("127.0.0.1", "local"))
        self.assertTrue(is_in("127.0.0.1", "all"))
        GOOGLE_DOT_COM = "74.125.237.20"
        self.assertFalse(is_in(GOOGLE_DOT_COM, "local"))
        self.assertTrue(is_in(GOOGLE_DOT_COM, "all"))
        #  Test with a list of stuff
        ips = ["127.0.0.1", "127.0.1.*"]
        self.assertTrue(is_in("127.0.0.1", ips))
        self.assertTrue(is_in("127.0.1.1", ips))
        self.assertFalse(is_in("127.0.0.2", ips))
        self.assertTrue(is_in("127.0.1.2", ips))
        #  Test with a string-list of stuff
        ips = "123.123.0.0/16 local"
        self.assertTrue(is_in("127.0.0.1", ips))
        self.assertTrue(is_in("127.0.1.1", ips))
        self.assertTrue(is_in("123.123.1.1", ips))
        self.assertFalse(is_in("124.0.0.1", ips))
        #  Test with various strange inputs to the parser
        self.assertTrue(is_in("127.0.0.1", IPAddress("127.0.0.1")))
        self.assertTrue(is_in("127.0.0.1", int(IPAddress("127.0.0.1"))))
        self.assertTrue(is_in("127.0.0.1", IPNetwork("127.0.0.1/8")))
        self.assertTrue(is_in("127.0.0.1", IPGlob("127.0.0.*")))
        self.assertTrue(is_in("127.0.0.1", IPRange("127.0.0.1", "127.0.0.2")))
        self.assertTrue(is_in("127.0.0.1", IPSet(["127.0.0.1/8"])))
        self.assertFalse(is_in("127.0.0.1", ""))
        self.assertFalse(is_in("127.0.0.1", None))
        self.assertRaises(ValueError, is_in, "127.0.0.1", 3.14159)
        self.assertRaises(ValueError, is_in, "127.0.0.1", Ellipsis)

    def test_from_settings(self):
        settings = {
            "foo": "bar",
            "ipauth.ipaddrs": "123.123.0.1 124.124.0.1/16",
            "ipauth.userid": "one",
            "ipauth.principals": "two three",
            "otherauth.ipaddrs": "127.0.0.*",
            "otherauth.userid": "other",
            "otherauth.proxies": "127.0.0.1 127.0.0.2",
        }
        # Try basic instantiation.
        auth = IPAuthenticationPolicy.from_settings(settings)
        self.assertTrue(IPAddress("123.123.0.1") in auth.ipaddrs)
        self.assertEquals(auth.userid, "one")
        self.assertEquals(auth.principals, ["two", "three"])
        self.assertEquals(auth.proxies, IPSet([]))
        # Try instantiation with custom prefix.
        auth = IPAuthenticationPolicy.from_settings(settings,
                                                    prefix="otherauth.")
        self.assertTrue(IPAddress("127.0.0.1") in auth.ipaddrs)
        self.assertEquals(auth.userid, "other")
        self.assertEquals(auth.principals, [])
        self.assertTrue(IPAddress("127.0.0.1") in auth.proxies)
        self.assertTrue(IPAddress("127.0.0.2") in auth.proxies)
        self.assertFalse(IPAddress("127.0.0.3") in auth.proxies)
        # Try instantiation with extra keywords
        auth = IPAuthenticationPolicy.from_settings(settings,
                                                    prefix="otherauth.",
                                                    userid="overwritten")
        self.assertTrue(IPAddress("127.0.0.1") in auth.ipaddrs)
        self.assertEquals(auth.userid, "overwritten")
        self.assertEquals(auth.principals, [])
        self.assertTrue(IPAddress("127.0.0.1") in auth.proxies)
        self.assertTrue(IPAddress("127.0.0.2") in auth.proxies)
        self.assertFalse(IPAddress("127.0.0.3") in auth.proxies)

    def test_includeme(self):
        self.config.add_settings({"ipauth.userid": "user"})
        includeme(self.config)
        policy = self.config.registry.getUtility(IAuthenticationPolicy)
        self.assertEquals(policy.userid, "user")
