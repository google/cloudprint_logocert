"""Copyright 2015 Google Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


Methods to interact with higher level network protocols.

Transport will provide methods to send and receive data using higher level
protocols like HTTP, mDNS, etc.

This module is dependent on modules from the LogoCert pacakge.
"""

import mimetypes
import os
import socket  # In order to set a default timeout.
import urllib
import urllib2

import _common
from _config import Constants
from _jsonparser import JsonParser
import _log


class Transport(object):
  """Send and receive network messages and communication."""

  def __init__(self):
    """Get a reference to a logger object."""
    self.logger = _log.GetLogger('LogoCert')
    self.jparser = JsonParser()
    socket.setdefaulttimeout(Constants.URL['TIMEOUT'])

  def HTTPReq(self, url, auth_token=None, cloudprint=True, data=None,
              headers=None, printdata=None, user=None):
    """Send a HTTP Get or Post Request to a remote server.

    Args:
      url: string, url to send request to.
      auth_token: string, Google auth token of user.
      cloudprint: boolean, True = add CloudPrint Header.
      data: dictionary, data to send in request.
      headers: dict, key/value pairs of HTTP header.
      printdata: encoded data for printing.
      user: string, email address of user.
    Returns:
      dict: response with keys code, headers, and data.
    If data is not None (it has a value) this will become a Post request.
    """
    response = {'code': None,
                'headers': None,
                'data': None,
               }

    if not headers:
      headers = {}
    self.logger.debug('User = %s', user)
    if user is not None:
      self.logger.debug('Found user: %s', user)
      # Must urlencode the user string.
      userdict = {'user': user}
      encoded_user = urllib.urlencode(userdict)
      url += '&'
      url += encoded_user
    self.url = url
    self.user = user
    self.logger.debug('Using headers: %s', headers)
    self.logger.debug('Accessing URL: %s', url)

    request = urllib2.Request(self.url)
    if auth_token:
      self.logger.debug('Using Auth Token: %s', auth_token)
      request.add_header('Authorization', 'Bearer %s' % auth_token)
    if cloudprint:
      request.add_header('X-CloudPrint-Proxy', 'GCPLogoCert')
    if headers:
      for header in headers:
        self.logger.debug('Using header: %s:%s', header, headers[header])
        request.add_header(header, headers[header])
    # If data = '', we want to execute a POST, so use: if data is not None.
    if data is not None:
      edata = urllib.urlencode(data)
      self.logger.debug('Executing a HTTP POST request')
      request.add_data(edata)
    else:
      self.logger.debug('Executing a HTTP Get request')
    if printdata is not None:
      request.add_data(printdata)
      self.logger.debug('Adding print data.')

    try:
      r = urllib2.urlopen(request)
    except urllib2.URLError as e:  # This includes the HTTPError subclass.
      if hasattr(e, 'code'):
        response['code'] = e.code
        self.logger.warning('Return Code: %s', e.code)
      if hasattr(e, 'reason'):
        response['data'] = e.reason
        self.logger.warning(e.reason)
      self.logger.debug(response)
      return response

    response['code'] = r.getcode()
    response['headers'] = r.info()
    response['data'] = r.read()
    self.LogData(response)
    self.logger.debug(response)
    r.close()

    return response

  def SendFile(self, url, pathname, headers=None, content_type=None):
    """Upload a file to a service.

    Args:
      url: string, url to send the file to.
      pathname: string, pathname of file to send.
      headers: key/value pairs of HTTP header.
      content_type: mimetype of file.
    Returns:
      boolean: True = No errors, False = errors.
    """
    if not content_type:
      content_type = mimetypes.guess_type(pathname)
      if not content_type:
        content_type = 'text/plain'

    if not headers:
      headers = {}

    length = os.path.getsize(pathname)
    data = _common.ReadFile(pathname)
    request = urllib2.Request(url, data)
    if headers:
      for header in headers:
        self.logger.debug('Using header: %s:%s', header, headers[header])
        request.add_header(header, headers[header])
    request.add_header('Cache-Control', 'no-cache')
    request.add_header('Content-Length', '%d' % length)
    request.add_header('Content-Type', content_type)
    response = urllib2.urlopen(request).read().strip()
    self.LogData(response)
    return response

  def LogData(self, response):
    """Log all response headers and data.

    Args:
      response: dictionary from a response from Distributer.SendHTTPReq().
    Returns:
      boolean: True = return code is 200, False = return code is not 200.
    If this function is called and the log level is not debug, this method will
    only log the return code.
    """

    info = self.jparser.Read(response['data'])
    if info['json']:
      self.logger.debug(self.jparser.Print(info['json']))
      for k in info:
        self.logger.debug('Data item: %s\nData Value: %s', k, info[k])
    if response['headers']:
      self.logger.debug('Headers returned from query:')
      for header in response['headers']:
        self.logger.debug('Header Key: %s\nHeader Value: %s', header,
                          response['headers'][header])
    if response['code']:
      self.logger.info('HTTP device return code: %s', response['code'])
      if response['code'] == 200:
        return True
      else:
        return False
    else:
      return False
