"""Copyright 2016 Google Inc. All Rights Reserved.

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

This module is dependent on modules from the LogoCert package.
"""

import socket  # In order to set a default timeout.
import requests
import time
import _oauth2

from _config import Constants


class Transport(object):
  """Send and receive network messages and communication."""

  def refreshOauthToken():
    """Check if the time token from the test is more than 30 mins and if so
    refresh the oauth access token and update the respective objects.
    
    Oauth Access tokens expire in 1 hr, but we refresh every 30 minutes just
    to stay on the safe side 
    """
    if headers is not None and 'Authorization' in headers:
      if time.time() > Constants.AUTH['PREV_TOKEN_TIME'] + 1800:
        Constants.AUTH['PREV_TOKEN_TIME'] = time.time()
        _oauth2.Oauth2.RefreshToken()
        _device.auth_token = Constants.AUTH['ACCESS']
        _gcp.auth_token = Constants.AUTH['ACCESS']
  
  def __init__(self, logger):
    """Get a reference to a logger object and JsonParser.

    Args:
        logger: initialized logger object.
    """
    self.logger = logger
    socket.setdefaulttimeout(Constants.URL['TIMEOUT'])

  def HTTPPost(self, url, headers=None, params=None, data=None, files=None):
    """Send a HTTP Post Request to a remote server.

    Args:
      url: string, url to send request to.
      headers: dict, key/value pairs of HTTP header.
      params: key/value pairs of parameters.
      data: data to post
      files: file to post
    Returns:
      dict: Response object, with keys code, headers, and data.
    """
    response = requests.post(url, headers=headers, params=params, data=data,
                             files=files)

    if response is None:
      self.logger.info('HTTP(S) POST to %s failed', url)
      return None

    self.LogResponseData(response)
    refreshOauthToken()
    return response

  def HTTPGet(self, url, headers=None, params=None):
    """Send a HTTP Get Request to a remote server.

    Args:
      url: string, url to send request to.
      headers: dict, key/value pairs of HTTP header.
      params: key/value pairs of parameters.
    Returns:
      dict: Response object, with keys code, headers, and data.
    """
    response = requests.get(url, headers=headers, params=params)

    if response is None:
      self.logger.info('HTTP(S) GET for %s failed', url)
      return None

    self.LogResponseData(response)
    refreshOauthToken()
    return response

  def LogResponseData(self, response):
    """Log all response headers and data.

    If this function is called and the log level is not debug, this method will
    only log the return code.

    Args:
      response: Response object from the requests module.
    """
    self.logger.debug('HTTP device return code: %s', response.status_code)

    self.logger.debug('Headers returned from query:')
    for k,v in response.headers.iteritems():
      self.logger.debug('Header Key: %s\nHeader Value: %s', k, v)

    self.logger.debug('Response Data:')
    try:
      info = response.json()
    except ValueError:
      self.logger.info('No JSON object in response')
    else:
      for k in info:
        self.logger.debug('Data item: %s\nData Value: %s', k, info[k])
