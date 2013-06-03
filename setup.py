#!/usr/bin/env python

from distutils.core import setup

setup(name='oauth2proxy',
      version='0.5',
      description='HTTP Proxy that lets Basic-capable clients talk to OAuth2 servers.',
      author='Joe Koberg',
      author_email='joe.koberg@versionone.com',
      packages=['oauth2proxy'],
      requires=[
        "paste",
        "wsgiproxy"
        "oauth2client"
        "urllib3"
      ]
     )