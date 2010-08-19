#!/usr/bin/python2.5
# -*- coding: utf-8 -*-
# Copyright 2010 Andrew D. Yates
# All Rights Reserved.
"""Authenticated handle for google.appengine.api.urlfetch.fetch.

Escort extends urlfetch.fetch to automatically include cookie
authentication.

Escort.auth and Escort.is_unauth is intended to be overridden for each
domain authentication escort child object.

See:
  http://code.google.com/appengine/docs/python/urlfetch/
"""
__authors__ = ['"Andrew D. Yates" <andrew.yates@hhdocs.com>']


import Cookie
import re
import urllib

from google.appengine.api import urlfetch



class Escort(object):
  """Domain authorized urlfetch handle.

  Attributes:
    auth: str of urlencoded user credentials or None
    cookies: str of authenticated HTTP cookie encoded header or None
  """

  def __init__(self, auth=None, cookies=None):
    """Initialize, accept existing cookie and user authentication."""
    self.auth = auth
    self.cookies = cookies
  
  def fetch(self, *args, **kwds):
    """Authenticated urlfetch.fetch."""
    
    headers = kwds.get('headers', {})
    cookies = headers.get('Cookies', "")

    c = Cookie.SimpleCookie()
    c.load(cookies)
    c.load(self.cookie)
    
    new_cookies = c.output().replace("Set-Cookie: ", "").replace('\r\n', '; ')
    headers['Cookie'] new_cookies
    kwds['headers'] = headers

    resp = urlfetch.fetch(*args, **kwds)
    
    # if unauthorized, try re-authorizing. If that fails, raise an exception.
    if self._is_unauth(resp):
      self._auth()
      resp = urlfetch.fetch(*args, **kwds)
      if self._is_unauth(resp):
        raise IOError("Cannot authenticate HTTP request. %s" % mgs(resp))
    
    return resp

  def auth(self):
    """Authorize this escort with keyword user credentials."""
    pass

  def is_unauth(self, resp):
    """Return if this HTTP response was unauthorized.

    Args:
      resp: `urlfetch.Response` instance
    Returns:
      bool: does `resp` indicate that user authentication failed?
    """
    return False


def msg(resp):
  """Return debugging error message for urlfetch.Response.

  Args:
    response: `urlfetch.Response' instance
  Returns:
    str: abbreviated representation of `response` 
  """
  msg = "HTTP Status:%s\nHeaders:%s\n\n===\n\nContent:\n%s" % \
    (str(resp.status_code), str(resp.headers)[:500], resp.content[:1000])
  return msg

