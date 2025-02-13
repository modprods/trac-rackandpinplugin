README.MD
# trac-rackandpinplugin

Trac plugin to authenticate users against [Rack&Pin](https://rackandpin.com/) service.

https://trac-hacks.org/wiki/TracRackAndPin

## Installation

Requirements:

    Requests library: https://pypi.python.org/pypi/requests-oauthlib
    $ pip install requests_oauthlib

Deploy to a specific Trac environment:

    $ cd /path/to/pluginsource
    $ python setup.py bdist_egg
    $ cp dist/*.egg /path/to/projenv/plugins

Enable plugin in trac.ini:

    [components]
    rackandpin.api.oauth2plugin = enabled
    trac.web.auth.loginmodule = disabled

Configuration in trac.ini :

    [trac]
    base_url = <trac URI>
      
    [rackandpin]
    client_id = <CLIENT_ID_STRING>
    client_secret = <CLIENT_SECRET_STRING>
    production_id = <PRODUCTION_ID_INTEGER>
    api_base_url = https://rackandpin.com

To authenticate against _any_ valid Rack&Pin user omit production_id line

    [metanav]
    logout.redirect = https://rackandpin.com/logout_redirect?next=<trac URI>

This line required to log user out of Rack&Pin completely

## Migrating from HTTP Basic Auth to OAUTH2 Auth

If you have an existing trac using HTTP Basic Auth there is no way to logout.
https://trac.edgewall.org/ticket/791

You will need to restart your browser to start using OAUTH. Any sessions already authenticated by the web browser will remain open regardless of OAUTH2 privileges

By default anoymous users have a number of permissions. You may wish to remove these and restrict visibility of the trac content to authenticated users.

e.g.

Administration | General | Permissions | Manage Permissions and Groups | Copy Permissions

Subject: anonymous
Target: authenticated
"Add"

Permissions
Select all anonymous permissions and "Remove selected items"

## License

Copyright (c) 2025, Mod Productions Pty Ltd
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in
   the documentation and/or other materials provided with the
   distribution.
3. The name of the author may not be used to endorse or promote
   products derived from this software without specific prior
   written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
