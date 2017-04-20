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


Some functions to get OAuth2 credentials.
"""

import httplib2
import requests

from _config import Constants

from oauth2client.client import OAuth2WebServerFlow
from oauth2client.file import Storage
from oauth2client.tools import run_flow
from oauth2client.tools import argparser


class Oauth2(object):
  """Send and receive network messages and communication."""

  def __init__(self, logger):
    """Get a reference to a logger object and JsonParser.

    Args:
        logger: initialized logger object.
    """
    self.logger = logger
    self.storage = Storage(Constants.AUTH['CRED_FILE'])

  def GetTokens(self):
    """Retrieve credentials."""
    if 'REFRESH' in Constants.AUTH:
      self.RefreshToken()
    else:
      creds = self.storage.get()
      if creds:
        Constants.AUTH['REFRESH'] = creds.refresh_token
        Constants.AUTH['ACCESS'] = creds.access_token
        self.RefreshToken()
      else:
        self.getNewTokens()


  def RefreshToken(self):
    """Get a new access token with an existing refresh token."""
    response = self.refreshTokenImpl()
    # If there is an error in the response, it means the current access token
    # has not yet expired.
    if 'access_token' in response:
      self.logger.info('Got new access token.')
      Constants.AUTH['ACCESS'] = response['access_token']
    else:
      self.logger.info('Using current access token.')


  def getNewTokens(self):
    """Get all new tokens for this user account.

    This process is described in detail here:
    https://developers.google.com/api-client-library/python/guide/aaa_oauth

    If there is a problem with the automation authorizing access, then you
    may need to manually access the permit_url while logged in as the test user
    you are using for this automation.
    """
    flow = OAuth2WebServerFlow( client_id = Constants.USER['CLIENT_ID'],
                                client_secret = Constants.USER['CLIENT_SECRET'],
                                login_hint= Constants.USER['EMAIL'],
                                redirect_uri= Constants.AUTH['REDIRECT'],
                                scope = Constants.AUTH['SCOPE'],
                                user_agent = Constants.AUTH['USER_AGENT'],
                                approval_prompt = 'force')

    http = httplib2.Http()
    flags = argparser.parse_args(args=[])

    # retrieves creds and stores it into storage
    creds = run_flow(flow, self.storage, flags=flags,http=http)

    if creds:
      Constants.AUTH['REFRESH'] = creds.refresh_token
      Constants.AUTH['ACCESS'] = creds.access_token
      self.RefreshToken()
    else:
      self.logger.error('Error getting authorization code.')

  def refreshTokenImpl(self):
    """Obtains a new token given a refresh token.

    Returns:
      The decoded response from the Google Accounts server, as a dict. Expected
      fields include 'access_token', 'expires_in', and 'refresh_token'.
    Before you execute this function make sure you've added your account's
    refresh token. This is done automatically when the LogoCert class is
    initialized.
    """
    params = {}
    params['client_id'] = Constants.USER['CLIENT_ID']
    params['client_secret'] = Constants.USER['CLIENT_SECRET']
    params['refresh_token'] = Constants.AUTH['REFRESH']
    params['grant_type'] = 'refresh_token'

    headers = {
        'User-Agent': 'LogoCert Client',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'text/html, */*',
        }

    request_url = Constants.OAUTH_TOKEN

    res = requests.post(request_url, headers=headers, params=params)

    return res.json()
