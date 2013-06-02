
import json, random, logging, os, sys, urlparse

logging.basicConfig(level=logging.DEBUG)

from paste import httpserver
from paste.auth.basic import AuthBasicHandler
from wsgiproxy.app import WSGIProxyApp
import httplib2
import urllib3
    
# Bring in Google oauth2 library functions

import oauth2client
import oauth2client.clientsecrets
import oauth2client.tools
from oauth2client.file import Storage
from oauth2client.client import flow_from_clientsecrets 


class JsonUserPasswordFile:
    def __init__(self, filename="local_user_creds.json"):
        self.filename = filename

    def randchars(self, count=10, alphabet='0123456789abcdefghijklmnopqrstuvwxyz'):
        return ''.join(random.choice(alphabet) for n in range(count))

    def read_user_details(self):
        text = open(self.filename, "r").read()
        data = json.loads(text)
        return {
            "username": data["username"],
            "password": data["password"]
            }

    def get_user_details(self):
        try:
            return self.read_user_details()
        except IOError:
            newuser = {
                "username": self.randchars(),
                "password": self.randchars()
                }
            open(self.filename, "w").write(json.dumps(newuser))
            logging.warn("Created local user %(username)s:%(password)s"%newuser)
        return self.read_user_details()

    def check_user_pass(self, environ, username, password):
        creds = self.get_user_details()
        return creds["username"] == username and creds["password"] == password


class DealWithUnauthorizedError(Exception): pass

class OAuth2Proxy(object):
    def __init__(self, scopes, client_secrets_file='client_secrets.json', oauth2_creds_file='stored_credentials.json', run_grant=True):
        self.client_secrets_file = client_secrets_file
        self.oauth2_creds_file = oauth2_creds_file
        self.oauth_client = httplib2.Http()
        self.open_clientsecrets(scopes)
        self.credentials = self.storage.get()
        if not self.credentials:
            if run_grant:
                self.credentials = oauth2client.tools.run(self.flow, self.storage, self.oauth_client)
            else:
                logging.error("Please obtain the Oauth2 permission grant from the user by re-running this tool with option TODO.")
                raise Exception("Missing oauth2 credentials in %s"%(self.oauth2_creds_file,))

        parts = urlparse.urlparse(self.secrets_data["server_base_uri"])
        logging.debug(parts)
        scheme, netloc, path, params, query, fragment = parts
        self.proxy_destination = urlparse.urlunparse((scheme, netloc, "", params, query, fragment))
        logging.info("Proxying to " + self.proxy_destination)
        self.proxy = WSGIProxyApp(self.proxy_destination)

    def open_clientsecrets(self, scopes_requested):
        try:
            self.flow = flow_from_clientsecrets(
                self.client_secrets_file,
                scope = scopes_requested ,
                redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
                )
            self.storage = Storage(self.oauth2_creds_file)
            raw_secrets_data = json.load(open(self.client_secrets_file,"r"))
            self.secrets_data = raw_secrets_data.get("installed", raw_secrets_data.get("web", {}))
        except oauth2client.clientsecrets.InvalidClientSecretsError:
            logging.error("Please download the %s file from the VersionOne permitted applications page and save it in the current directory (%s)" %(self.client_secrets_file, os.getcwd()))
            sys.exit(1)

    def refresh_tokens(self):
        return self.credentials.refresh(self.oauth_client)

    def addheaders(self, environ):
        headers = {}
        self.credentials.apply(headers)
        for header, content in headers.items():
            environ["HTTP_"+header.upper()] = content
        logging.debug(environ)
        return environ

    def __call__(self, environ, upstream_start_response):
        # the proxy will call this function when it has made its
        # request to the downstream (versionone) server and has a
        # response header from it.
        def my_start_response(statusline, headerlist):
            logging.debug((statusline, headerlist))
            if statusline.startswith('401'):
                raise DealWithUnauthorizedError((statusline,headerlist))
            return upstream_start_response(statusline, headerlist)

        # we try once, and if unauthed, refresh and reissue the request.
        try:
            self.addheaders(environ)
            return self.proxy(environ, my_start_response)
        except DealWithUnauthorizedError:
            self.refresh_tokens()
            self.addheaders(environ)
            return self.proxy(environ, my_start_response)


if __name__ == '__main__':
    # Handle command-line args for google oauth2 library

    import gflags
    FLAGS = gflags.FLAGS
    try:
        argv = FLAGS(sys.argv)  # parse flags
    except gflags.FlagsError, e:
        print '%s\\nUsage: %s ARGS\\n%s' % (e, sys.argv[0], FLAGS)
        sys.exit(1)

    passfile = JsonUserPasswordFile()
    proxy = OAuth2Proxy(scopes="query-api-1.0")
    authed_app = AuthBasicHandler(proxy, "oauth2proxy", passfile.check_user_pass)
    httpserver.serve(authed_app, host='127.0.0.1', port='5180')
