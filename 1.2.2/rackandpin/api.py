from trac.core import *
from trac.web.chrome import Chrome
from trac.web.auth import LoginModule
from trac.web.chrome import add_notice, add_warning
from trac.util.html import tag
from trac.util.translation import _, tag_

import re
# import time
import urlparse
from requests_oauthlib import OAuth2Session

import os

# import logging
# logger = logging(__file_)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'

# Endpoint on this application for Rack&Pin OAuth
TRAC_BASE_URL = 'http://localhost:8001'
API_BASE_URL = 'https://rackandpin.com'

# OAuth endpoints given in the Rack&Pin API documentation
# authorization_base_url with production id will only authorize against
# that hub
# without the id, any valid Rack&Pin user can authorize

PRODUCTION_ID = None

SCOPE = [
    "read"
]


# member_authorization_url = "%s/api/member/%d" % (api_base_url,
#                                                  production_id)


class OAuth2Plugin(LoginModule):
    def match_request(self, req):
        return re.match(r"/oauth2callback\??.*", req.path_info) or \
            LoginModule.match_request(self, req)

    def get_navigation_items(self, req):
        if req.is_authenticated:
            yield ('metanav', 'login',
                   tag_("logged in as %(user)s",
                        user=Chrome(self.env).authorinfo(req, req.authname)))
            yield ('metanav', 'logout',
                   tag.form(
                       tag.div(
                           tag.button(_("Logout"), name='logout',
                                      type='submit'),
                           tag.input(type='hidden', name='__FORM_TOKEN',
                                     value=req.form_token)
                       ),
                       action=req.href.logout(), method='post',
                       id='logout', class_='trac-logout'))
        else:
            req.session['ORIGINAL_URL'] = req.href(req.path_info)
            self.env.log.debug("*** ORIGINAL_URL: %r", req.href(req.path_info))
            req.session.save() # causes no code to appear if included
            yield ('metanav', 'login',
                   tag.a(_("Login"), href=req.href.login())
            )

    def process_request(self, req):
        if req.path_info.startswith("/login"):
            self._do_oauth2_login(req)
        elif req.path_info.startswith("/oauth2callback"):
            self._do_callback(req)
        else:
            LoginModule.process_request(self, req)
        req.redirect(self.env.abs_href())

    def _do_oauth2_login(self, req):
        trac_base_url = self.config.get('trac', 'base_url', TRAC_BASE_URL)
        redirect_uri = trac_base_url + '/oauth2callback'
        api_base_url = self.config.get('rackandpin', 'api_base_url', API_BASE_URL)
        production_id = self.config.get('rackandpin', 'production_id', PRODUCTION_ID)
        client_id = self.config.get('rackandpin', 'client_id', '')
        scope = self.config.get('rackandpin', 'scope', SCOPE)

        if production_id:
            authorization_base_url = api_base_url + "/o/authorize/%s/" % production_id
        else:
            authorization_base_url = api_base_url + "/o/authorize/"
        self.env.log.debug("*** Hey, auth url is %r ***",
                           authorization_base_url)
        session = OAuth2Session(client_id, scope=scope,
                                redirect_uri=redirect_uri)
        authorization_url, state = session.authorization_url(
            authorization_base_url,
            access_type="offline", prompt="select_account")

        # State is used to prevent CSRF, keep this for later.
        req.session['OAUTH_STATE'] = state
        req.redirect(authorization_url)

    def _do_callback(self, req):
        trac_base_url = self.config.get('project', 'url', TRAC_BASE_URL)
        api_base_url = self.config.get('rackandpin', 'api_base_url', API_BASE_URL)
        client_id = self.config.get('rackandpin', 'client_id', '')
        client_secret = self.config.get('rackandpin', 'client_secret', '')

        token_url = api_base_url + "/o/token/"
        redirect_uri = trac_base_url + '/oauth2callback'
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
        member_authorization_url = "%s/api/username" % api_base_url

        try:
            r = session.get(member_authorization_url)
            authname = r.content
        except Exception:
            self.env.log.debug("*** Hey, this user not authorized ***")
            add_warning(req, """Authorization failed for this user.
                                Contact your production manager""")

            raise Exception("Authorization failed")

        req.environ["REMOTE_USER"] = authname
        #        req.environ["REMOTE_USER"] = "marge"
        original_url = req.session.get('ORIGINAL_URL')
        if original_url:
            self.env.log.debug("retreived original_url: %r", original_url)
            add_warning(req,"original_url: " + original_url)
            del req.session['ORIGINAL_URL']  # Clear it to avoid infinite loops
            req.session.save()
            # req.session.save()  # Ensure session changes are saved
            LoginModule._do_login(self, req)
            req.redirect(original_url)
        else:
            self.env.log.debug("no original_url")
            LoginModule._do_login(self, req)
        # LoginModule._do_login(self, req)
