oauth2proxy
===========

A proxy that wraps requests with Oauth2 headers, so non-oauth2 HTTP clients can talk to an OAuth2 protected server.

QUICKSTART:

Install git, Python 2.7, and virtualenv.  Then:

	git clone git://github.com/versionone/oauth2proxy.git
	cd oauth2proxy
	virtualenv myenv
	. ./myenv/Scripts/activate
	pip install urllib3
	pip install oauth2client
	pip install paste
	pip install wsgiproxy

	# download client_secrets.json from server and place here

	python oauth2proxy/proxy.py --noauth_local_webserver

	# configure client to connect to http://localhost:5180/ ; copy local username and password from console

	# follow prompt to webserver URL and copy/paste access code

	# Enjoy!


Security Notes
--------------

Using SSL for the destination server is mandatory to protect OAuth2 authorization credentials carried in the request headers. (The same is true of Basic, Header, and Cookie auth as well)

For higher security, disallow unknown certs with --noanycert and register the server's known SSL cert.



Configuration
-------------

The client takes its oauth2 and destination configuration from the "client_secrets.json" file produced by the "Download JSON" link of a VersionOne server instance.  This file is the same format as that expected by the Google oauth2client library, with the addition of the "server_base_uri" and "expires_on" fields.

	{
	  "installed": {
	    "client_id": "client_we682vr9",
	    "client_name": "Oauth2 proxy on joes",
	    "client_secret": "ppxhrs2ycs5ojsw22vs3",
	    "redirect_uris": [
	      "urn:ietf:wg:oauth:2.0:oob"
	    ],
	    "auth_uri": "https://www7.v1host.com//V1Production/oauth.mvc/auth",
	    "token_uri": "https://www7.v1host.com//V1Production/oauth.mvc/token",
	    "server_base_uri": "https://www7.v1host.com/V1Production",
	    "expires_on": "9999-12-31T23:59:59.9999999"
	  }
	}



Options
-------

  * --destination=<http server>   Server to proxy requests to

  * --scope=<scopes>   OAuth2 scope to request in the permissions grant

  * --secrets=filename   Filename for json file containing oauth2 client secret, id, and server base uri

  * --creds=filename   Filename for json file containing stored oauth2 tokens

  * --localuser=filename   Filename for json file containing local "Basic" auth username/password.

  * --prompt=true   Prompt user for credentials grant if not found in stored credentials file.  Without --noauth_webserver_local, will start up a local webserver to receive the access token redirect.

  * --anycert=true   Accept any SSL certificate from the proxied server.  For higher security, turn this off and register the server's known cert to prevent man-in-the-middle attacks.

  * --listenaddr=127.0.0.1   IP address to accept connections on.  WARNING: It is recommended that you only run this proxy on the same machine as the client so that client-to-proxy traffic is not observable.

  * --listenport=5180   TCP port number to accept connections on.

