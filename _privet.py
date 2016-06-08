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


A module to support the Privet (Local Discovery) API.

Use this module to conduct tests that interact with the Privet protocol. The
Privet class will provide the needed methods to send, receive, and parse
messages from privet clients (for example, a printer).
"""


class Privet(object):
  """Contains methods to send and receive Privet Protocol messages."""

  def __init__(self, logger):
    """Get a reference to a logger object. Set some initial dictionaries.
    
    Args:
      logger: initialized logger object.
    """
    self.logger = logger
    self.api_names = ['accesstoken', 'capabilities', 'info', 'INVALID',
                      'printer']
    self.reg_actions = ['start', 'cancel', 'getClaimToken', 'complete',
                        'invalid']
    self.printer_api = ['createjob', 'jobstate', 'submitdoc']
    self.required_fields = ['manufacturer', 'model', 'firmware', 'update_url',
                            'version', 'x-privet-token']

    self.headers_empty = {'X-Privet-Token': '""'}
    self.headers_invalid = {'X-Privet-Token': 'INVALID'}
    self.headers_missing = {}

  def SetPrivetUrls(self, device_ip, device_port):
    """Construct a dictionary of URLs that Privet clients provide.

    Args:
      device_ip: string, IP address of the privet client.
      device_port: integer, TCP port number of device.
    Returns:
      dictionary where key = action and value = URL.
    """
    urls = {}
    urls['register'] = {}  # Register has multiple actions.
    device_url = 'http://%s:%d' % (device_ip, device_port)

    for name in self.api_names:
      urls[name] = '%s/privet/%s' % (device_url, name)
    for name in self.printer_api:
      urls[name] = '%s/privet/printer/%s' % (device_url, name)
    for action in self.reg_actions:
      urls['register'][action] = '%s/privet/%s?action=%s' % (
          device_url, 'register', action)

    return urls
