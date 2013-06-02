oauth2proxy
===========

A proxy that wraps requests with Oauth2 headers, so non-oauth2 HTTP clients can talk to an OAuth2 protected server.

QUICKSTART::

pip install urllib3
pip install oauth2client
pip install paste
pip install wsgiproxy

Download the "client_secrets.json" file from the VersionOne instance and place it next to the "proxy.py" file.

python oauth2proxy/proxy.py --noauth_local_webserver

Initial random username and password will be logged to console, and stored in local_user_creds.json

Direct requests to http://localhost:5180/ . They must carry Basic authorization with the usernamd and password from local_user_creds.json.

