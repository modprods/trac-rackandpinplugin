from trac.core import *
from trac.web.auth import LoginModule
from trac.web.chrome import add_notice

import re
import time
import urlparse
from requests_oauthlib import OAuth2Session

import os

# import logging
# logger = logging(__file_)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'

# Credentials you get from registering a new application
# hub
client_id = 'w5BfBV4w0MvMM3XQtrC6Z8HwNyLZC7w4jj0AmMgf'
client_secret = '6ASUeHVYPaZZAGhknfpuOKbeMWDL1oQmkWyVHeN3Rf85wRpcdkYh4uNeYrtaKrgf8C2C28pEfnsfoAFAXLmRnDQcFlkatDTPuw5HH84rNLhSscbF6lgdBj0y1XX367pE'


# provider sandbox
# client_id = 'ZWyhfRxCzM6bie9HCmnng7upNJ9tVrh9FxcTCSfk'
# client_secret = 'pLIbRJYlaAM0OfkKOmlylSkk1xyr7paNREIBYv4XAbzMPADE6bvNIwI2rhSw9oupkXzBk3H05EhpjnE2V8XuickiKO52DT4kGdkfz2IXabuLTYiwB8ZEfUGsG1prbczZ'

# Endpoint on this application for Rack&Pin OAuth
trac_base_url = 'http://localhost:8001'
api_base_url = 'https://localhost:8000'
redirect_uri = trac_base_url + '/oauth2callback'

# OAuth endpoints given in the Rack&Pin API documentation

authorization_base_url = api_base_url + "/o/authorize/"
token_url = api_base_url + "/o/token/"
scope = [
    "read"
]
production_id = 41
member_authorization_url = "%s/api/member/%d" % (api_base_url,
                                                 production_id)


class OAuth2Plugin(LoginModule):
    def match_request(self, req):
        return re.match("/oauth2callback\??.*", req.path_info) or \
            LoginModule.match_request(self, req)

    def process_request(self, req):
        self.env.log.debug("*** Hey, mmeber url is %r ***",
                           member_authorization_url)
        if req.path_info.startswith("/login"):
            self._do_oauth2_login(req)
        elif req.path_info.startswith("/oauth2callback"):
            self._do_callback(req)
        else:
            LoginModule.process_request(self, req)
        req.redirect(self.env.abs_href())

    def _do_oauth2_login(self, req):

        session = OAuth2Session(client_id, scope=scope,
                                redirect_uri=redirect_uri)
        authorization_url, state = session.authorization_url(
            authorization_base_url,
            access_type="offline", prompt="select_account")

        # State is used to prevent CSRF, keep this for later.
        req.session['OAUTH_STATE'] = state
        req.redirect(authorization_url)

    def _do_callback(self, req):
        session = OAuth2Session(client_id, redirect_uri=redirect_uri,
                                state=req.session['OAUTH_STATE'])

        try:
            code = urlparse.parse_qs(req.query_string)["code"][0]
        except Exception:
            raise Exception("Received invalid query parameters.")
        # add_notice(req, "code:%s", code)
        self.env.log.debug("*** Hey, code is %r ***",
                           code)
        self.env.log.debug("*** Hey, token_url is %r ***",
                           token_url)
        token = session.fetch_token(token_url=token_url,
                                    client_secret=client_secret,
                                    code=code,
                                    verify=False)
        req.environ["oauth_token"] = token

        # add_notice(req, "token: %s", token)

        try:
            r = session.get(member_authorization_url)
            authname = r.content
        except:
            add_warning(req, "Authorization failed for this user. Contact your production manager")

            raise Exception("Authorization failed")

        req.environ["REMOTE_USER"] = authname
        #        req.environ["REMOTE_USER"] = "marge"
        LoginModule._do_login(self, req)
