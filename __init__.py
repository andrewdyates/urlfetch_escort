#!/usr/bin/python2.5
# -*- coding: utf-8 -*-
# Copyright 2010 Andrew D. Yates
# All Rights Reserved.
"""HTTP Cookie Authenticated urlfetch.fetch handle.

Escort is designed to handle broken or unpredictable websites which
may have complex authentication schemes and do not use standard HTTP
practices.

Example:
  >>> import escort
  ... class MyDomainSession(escort.Session):
  ...   POST_URL = "https://mydomain.com/login"
  ...   is_invalid(self, response):
  ...     response.status_code != 200
  ...   _user(self):
  ...     return {'user': 'myuser', 'pass': 'mypass'}
  ... 
  ... class MyDomainURLFetch(escort.URLFetch):
  ...   SESSION_CLASS = MyDomainSession
  ... 
  ... handle = MyDomainURLFetch()
  ... response = handle.fetch('http://mydomain.com/private')

To Do:
 * Implement entity_pb model caching.
 * Implement as single class
 * Test revised implementation
"""
__authors__ = ['"Andrew D. Yates" <andrew.yates@hhdocs.com>']


import Cookie
import os
import re
import urllib

from google.appengine.api import urlfetch
from google.appengine.api import memcache
from google.appengine.datastore import entity_pb
from google.appengine.ext import db
from google.appengine.ext.db import polymodel


# single cookie value from Set-Cookie header
RX_COOKIE = re.compile('^[^;, \n\t]+')

#  Headers for Google Chrome on OS X as of spring 2010
CHROME_OSX = {
  'User-Agent': 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_3; en-US) AppleWebKit/533.4 (KHTML, like Gecko) Chrome/5.0.375.38 Safari/533.4',
  'Accept': 'application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5',
  }


class SessionError(Exception):
  pass


class Session(polymodel.PolyModel):
  """Base class for domain-specific authenticated session as a datastore model.

  Ignore cookie parameters including expiration and path. Cookie
  path precedence and overflow is undefined.

  Attributes:
    cookie: str of set of session cookies as HTTP Cookie header value
    set_cookie_header: str of original set-cookie header value
    time_updated: datetime session was last updated
    invalid: bool if session token is no longer authenticated
  """

  cookie = db.TextProperty()
  set_cookie_header = db.TextProperty()
  time_updated = db.DateTimeProperty(auto_now=True)
  invalid = db.BooleanProperty()

  POST_URL = None
  POST_HEADERS = {
    'Accept': CHROME_OSX['Accept'],
    'User-Agent': CHROME_OSX['User-Agent'],
    }
  AUTH_ERRORS = []

  def _user(self):
    """Return user token. (e.g. username and password)

    Override to provide user credentials.

    Returns:
      {str:str} of user_token
    """
    raise NotImplementedError

  def _client(self):
    """Return transformed client token. (e.g. from HTML login form)

    Override to transform user token to client token.

    Returns:
      {str:str} request of client_token as urlfetch.fetch() args.
    """
    payload = self._user()
    token = {
      'url': self.POST_URL,
      'payload': urllib.urlencode(payload),
      'method': 'POST',
      'headers': self.POST_HEADERS.copy(),
      }
    return token

  def is_invalid(self, response):
    """Does HTTP response indicate an error or expired session?

    Override to implement site-specific session logic.

    Args:
      response: `urlfetch.Response` instance 
    Returns:
      bool: does the authentication for this response seem invalid?
    """
    return False

  def fetch(self):
    """Set own authenticated session cookie fetched from HTTP.

    Raises:
      SessionError: No session cookie returned by server.
    """
    request = self._client()
    response = urlfetch.fetch(**request)
    
    self.set_cookie_header = response.headers.get('Set-Cookie', None)
    if not self.set_cookie_header:
      raise SessionError("No session cookie returned by server.")

    # Reformat Set-Cookie Header to single cookie string
    c = Cookie.SimpleCookie().load(self.set_cookie_header)
    cookies = c.output().replace('Set-Cookie: ', '').split('\n')
    self.cookie = '; '.join([RX_COOKIE.match(cc).group(0) for cc in cookies])
      

class URLFetch(object):
  """Authenticated Cookie Session "urlfetch.fetch()" handle. 

  Attributes:
    SESSION_CLASS: (class) Session authentication class customized per domain.
    session: instance of custom `SessionClass`
    key: str of memcache key for `session` instance
  """

  # Abstract Class; override with children of `Session`
  SESSION_CLASS = None
  
  def __init__(self):
    """Initialize URLFetch with object Session class."""
    if not self.SESSION_CLASS:
      raise AttributeError("No SESSION_CLASS defined.")
    self.key = "%s:last_session" % str(self.SESSION_CLASS)
    self._set_session()

  def _new_session(self):
    """Refresh session authentication."""
    # TODO: update to use entity_pb
    self.session = self.SESSION_CLASS()
    self.session.fetch()
    self.session.save()
    # Update Memcache
    memcache.set(self.key, self.session, time=300)
  
  def _set_session(self):
    """Set session from last or new session.
    """
    # Try Memcache
    self.session = memcache.get(self.key)
    # Then Try Datastore
    if self.session is None:
      self.session = self.SESSION_CLASS.all()\
        .filter('invalid = ', False)\
        .order('-time_updated')\
        .get()
      # Update Memcache
      memcache.set(self.key, self.session, time=300)
    # Finally Try New Session
    if self.session is None:
      self._new_session()

  def _auth_fetch(self, *args, **request):
    """Fetch HTTP with session cookie.

    Args:
      **request: urlfetch.fetch HTTP request parameters
    Returns:
      response: `urlfetch.fetch` for **request merged with `self.session.cookie`
    """
    # Clean existing cookie header
    request['headers'] = request.get('headers', {})
    cookie_header = request['headers'].get('Cookie', '')
    cookie_header.rstrip('; \n\t')
    # Merge existing cookies with session cookies
    cookies_dict = dict(
      [c.split('=') for c in re.split('; *', cookie_header) if '=' in c]
      )
    session_cookies_dict = dict(
      [c.split('=') for c in re.split('; *', self.session.cookie) if '=' in c]
      )
    cookies_dict.update(session_cookies_dict)
    cookies = ["%s=%s" % (key, value) for key, value in cookies_dict.items()]
    request['headers']['Cookie'] = '; '.join(cookies)
    # Fetch HTTP with updated cookie header
    response = urlfetch.fetch(**request)
    return response

  def fetch(self, url, *args, **kwds):
    """urlfetch.fetch with automatic session cookie authentication.

    `fetch()` mimics urlfetch.fetch()
    See: http://code.google.com/appengine/docs/python/urlfetch/fetchfunction.html

    Args:
      **kwds: urlfetch.fetch HTTP request parameters
    Raises:
      SessionError: refreshing session fails
    Returns:
      `urlfetch.Response` as for urlfetch.fetch
    """
    response = self._auth_fetch(url=url, **kwds)
    # if invalid, get a new session and fetch `response` again
    if self.session.is_invalid(response):
      self.session.invalid = True
      self.session.save()
      self._new_session()
      response = self._auth_fetch(url=url, **kwds)
      # if still invalid after refresh, raise exception
      if self.session.is_invalid(response):
        raise SessionError(
          "Cannot refresh expired session. %s..." % self.msg(response))
    return response

  @classmethod
  def msg(cls, self):
    """Return debugging error message for HTTP response object.

    Args:
      response: `urlfetch.Response' instance returned from cls.fetch()
    Returns:
      str: representation of `response` for exception messages.
    """
    msg = "HTTP Status:%s\nHeaders:%s\n\n===\n\nContent:\n%s" % \
      (str(self.status_code), str(self.headers)[:500], self.content[:1000])
    return msg


