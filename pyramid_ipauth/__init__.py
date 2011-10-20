# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is pyramid_ipauth
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2011
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Ryan Kelly (ryan@rfk.id.au)
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****
"""
IP-based authentication policy for pyramid.
"""

from zope.interface import implements
from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Everyone, Authenticated

from pyramid_ipauth.utils import make_ip_set, check_ip_address


class IPAuthenticationPolicy(object):
    """An IP-based authentication policy for pyramid.

    This pyramid authentication policy assigns userid and/or effective
    principals based on the originating IP address of the request.

    You must specify a set of IP addresses against which to match, and may
    specify a userid and/or list of principals to apply.  For example, the
    following would authenticate all requests from the 192.168.0.* range as
    userid "myuser":

        IPAuthenticationPolicy(["192.168.0.0/24"], "myuser")

    The following would not authenticate as a particular userid, but would add
    "local" as an effective principal for the request (along with Everyone
    and Authenticated):

        IPAuthenticationPolicy(["127.0.0.0/24"], principals=["local"])

    By default this policy does not respect the X-Forwarded-For header since
    it can be easily spoofed.  If you want to respect X-Forwarded-For then you
    must specify a list of trusted proxies, and only forwarding declarations
    from these proxies will be respected:

        IPAuthenticationPolicy(["192.168.0.0/24"], "myuser",
                               proxies=["192.168.0.2"])

    """

    implements(IAuthenticationPolicy)

    def __init__(self, ipaddrs, userid=None, principals=None, proxies=None):
        self.ipaddrs = make_ip_set(ipaddrs)
        self.userid = userid
        self.principals = principals
        self.proxies = make_ip_set(proxies)

    @classmethod
    def from_settings(cls, settings, prefix="ipauth."):
        # Grab out all the settings keys that start with our prefix.
        ipauth_settings = {}
        for name, value in settings.iteritems():
            if not name.startswith(prefix):
                continue
            ipauth_settings[name[len(prefix):]] = value
        # Now look for specific keys
        ipaddrs = ipauth_settings.get("ipaddrs", "")
        userid = ipauth_settings.get("userid", None)
        principals = ipauth_settings.get("principals", "").split()
        proxies = ipauth_settings.get("proxies", None)
        # The constructor uses make_ip_set to parse out strings,
        # so we're free to just pass them on in.
        return cls(ipaddrs, userid, principals, proxies)

    def authenticated_userid(self, request):
        return self.unauthenticated_userid(request)

    def unauthenticated_userid(self, request):
        if not check_ip_address(request, self.ipaddrs, self.proxies):
            return None
        return self.userid

    def effective_principals(self, request):
        principals = [Everyone]
        if check_ip_address(request, self.ipaddrs, self.proxies):
            if self.userid is not None:
                principals.insert(0, self.userid)
            principals.append(Authenticated)
            if self.principals is not None:
                principals.extend(self.principals)
        return principals

    def remember(self, request, principal, **kw):
        pass

    def forget(self, request):
        pass


def includeme(config):
    """Include default ipauth settings into a pyramid config.

    This function provides a hook for pyramid to include the default settings
    for ip-based auth.  Activate it like so:

        config.include("pyramid_ipauth")

    This will activate an IPAuthenticationPolicy instance with settings taken
    from the the application settings as follows:

        * ipauth.ipaddrs:     list of ip addresses to authenticate
        * ipauth.userid:      the userid as which to authenticate
        * ipauth.principals:  additional principals as which to authenticate
        * ipauth.proxies:     list of ip addresses to trust as proxies

    IP addresses can be specified in a variety of formats, including single
    addresses ("1.2.3.4"), networks ("1.2.3.0/16"), and globs ("1.2.3.*").
    You can also provide a whitespace-separated list of addresses to handle
    discontiguous ranges.
    """
    # Grab the pyramid-wide settings, to look for any auth config.
    settings = config.get_settings().copy()
    # As a compatability hook for mozsvc, also load prefixed sections
    # from the Config object if present.
    mozcfg = settings.get("config")
    if mozcfg is not None:
        for section in mozcfg.sections():
            if section == "ipauth" or section.startswith("ipauth:"):
                setting_prefix = section.replace(":", ".")
                for name, value in mozcfg.get_map(section).iteritems():
                    settings[setting_prefix + "." + name] = value
    # Use the settings to construct an AuthenticationPolicy.
    authn_policy = IPAuthenticationPolicy.from_settings(settings)
    config.set_authentication_policy(authn_policy)
