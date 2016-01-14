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


A class to hold device attributes.

This class is used by the Cloud Print Logo Certification tool, to hold the
attributes of a device. Before the device attributes are fully populated,
the methods GetDeviceDetails and GetDeviceCDD must be run.
"""

import json

from _common import Extract
from _config import Constants
from _cpslib import GCPService
from _jsonparser import JsonParser
import _log
from _privet import Privet
from _transport import Transport


class Device(object):
  """The basic device object."""

  def __init__(self, auth_token, model=None):
    """Initialize a device object.

    Args:
      auth_token: string, auth_token of authenicated user.
      chromedriver: an initialized chromedriver object.
      model: string, unique model or name of device.
    """
    if model:
      self.model = model
    else:
      self.model = Constants.PRINTER['MODEL']
    self.logger = _log.GetLogger('LogoCert')
    self.ipv4 = Constants.PRINTER['IP']
    self.port = Constants.PRINTER['PORT']
    self.dev_id = None
    self.name = None
    self.gcp = GCPService(auth_token)
    self.status = None
    self.messages = []
    self.details = {}
    self.error_state = False
    self.cdd = {}
    self.info = None

    self.url = 'http://%s:%s' % (self.ipv4, self.port)
    self.logger.info('Device URL: %s', self.url)
    self.transport = Transport()
    self.jparser = JsonParser()
    self.headers = None
    self.privet = Privet()
    self.privet_url = self.privet.SetPrivetUrls(self.ipv4, self.port)
    self.GetPrivetInfo()

  def GetPrivetInfo(self):
    self.privet_info = {}
    response = self.transport.HTTPReq(self.privet_url['info'],
                                      headers=self.privet.headers_empty)
    info = self.jparser.Read(response['data'])
    if info['json']:
      for key in info:
        self.privet_info[key] = info[key]
        self.logger.debug('Privet Key: %s', key)
        self.logger.debug('Value: %s', info[key])
        self.logger.debug('--------------------------')
      if 'x-privet-token' in info:
        self.headers = {'X-Privet-Token': str(info['x-privet-token'])}
    else:
      if response['code']:
        self.logger.info('HTTP device return code: %s', response['code'])
      if response['headers']:
        self.logger.debug('HTTP Headers:  ')
        for key in response['headers']:
          self.logger.debug('%s: %s', key, response['headers'][key])
      if response['data']:
        self.logger.info('Data from response: %s', response['data'])

  def GetDeviceDetails(self):
    """Get the device details from our management page.

    This will populate a Device object with device name, status, state messages,
    and device details.
    """
    response = self.gcp.Search(self.model)
    for k in response['printers'][0]:
      if k == 'name':
        self.name = response['printers'][0][k]
      elif k == 'connectionStatus':
        self.status = response['printers'][0][k]
      elif k == 'id':
        self.dev_id = response['printers'][0][k]
      else:
        self.details[k] = response['printers'][0][k]
    #self.name = self.cloudprintmgr.GetPrinterName(self.model)
    #self.status = self.cloudprintmgr.GetPrinterState(self.model)
    #self.messages = self.cloudprintmgr.GetPrinterStateMessages(self.model)
    #self.details = self.cloudprintmgr.GetPrinterDetails(self.model)
    #self.error_state = self.cloudprintmgr.GetPrinterErrorState(self.model)


  def GetDeviceCDD(self, device_id):
    """Get device cdd and populate device object with the details.

    Args:
      device_id: string, Cloud Print device id.
    Returns:
      boolean: True = cdd details populated, False = cdd details not populated.
    """
    info = self.gcp.Printer(device_id)
    if self.ParseCDD(info):
      return True
    return False

  def ParseCDD(self, info):
    """Parse the CDD json string into a logical dictionary.

    Args:
      info: formatted data from /printer interface.
    Returns:
      boolean: True = CDD parsed, False = CDD not parsed.
    """

    if 'printers' in info:
      for k in info['printers'][0]:
        if k == 'capabilities':
          self.cdd['caps'] = {}
        else:
          self.cdd[k] = info['printers'][0][k]
    else:
      self.logger.error('Could not find printers in cdd.')
      return False
    for k in info['printers'][0]['capabilities']['printer']:
      self.cdd['caps'][k] = info['printers'][0]['capabilities']['printer'][k]
    return True

  def CancelRegistration(self):
    """Cancel Privet Registration that is in progress.

    Returns:
      return code from HTTP request.
    """
    cancel_url = self.privet_url['register']['cancel']
    self.logger.debug('Sending request to cancel Privet Registration.')
    response = self.transport.HTTPReq(cancel_url, data='',
                                      headers=self.headers,
                                      user=Constants.USER['EMAIL'])
    return response['code']

  def StartPrivetRegister(self):
    """Start a device registration using the Privet protocol.

    Returns:
      boolean: True = success, False = errors.
    """

    self.logger.debug('Registering device %s with Privet', self.ipv4)
    response = self.transport.HTTPReq(
        self.privet_url['register']['start'], data='',
        headers=self.headers, user=Constants.USER['EMAIL'])
    return self.transport.LogData(response)

  def GetPrivetClaimToken(self):
    """Attempt to get a Privet Claim Token.

    Returns:
      boolean: True = success, False = errors.
    """
    self.logger.debug('Getting Privet Claim Token.')
    counter = 0
    max_cycles = 5  # Don't loop more than this number of times.
    while counter < max_cycles:
      response = self.transport.HTTPReq(
          self.privet_url['register']['getClaimToken'], data='',
          headers=self.headers, user=Constants.USER['EMAIL'])
      self.transport.LogData(response)
      if 'token' in response['data']:
        self.claim_token = self.jparser.GetValue(response['data'], key='token')
        self.automated_claim_url = self.jparser.GetValue(
            response['data'], key='automated_claim_url')
        self.claim_url = self.jparser.GetValue(
            response['data'], key='claim_url')
        return True

      if 'error' in response['data']:
        self.logger.warning(response['data'])
        if 'pending_user_action' in response['data']:
          counter += 1
        else:
          return False

    return False  # If here, means unexpected condition, so return False.

  def SendClaimToken(self, auth_token):
    """Send a claim token to the Cloud Print service.

    Args:
      auth_token: string, auth token of user registering printer.
    Returns:
      boolean: True = success, False = errors.
    """
    if not self.claim_token:
      self.logger.error('Error: device does not have claim token.')
      self.logger.error('Cannot send empty token to Cloud Print Service.')
      return False
    if not self.automated_claim_url:
      self.logger.error('Error: expected automated_claim_url.')
      self.logger.error('Aborting SendClaimToken()')
      return False
    response = self.transport.HTTPReq(self.automated_claim_url,
                                      auth_token=auth_token, data='',
                                      user=Constants.USER['EMAIL'])
    self.transport.LogData(response)
    info = self.jparser.Read(response['data'])
    if info['json']:
      if info['success']:
        return True
      else:
        return False
    else:
      return False

  def FinishPrivetRegister(self):
    """Complete printer registration using Privet.

    Returns:
      boolean: True = success, False = errors.
    """

    self.logger.debug('Finishing printer registration.')
    response = self.transport.HTTPReq(
        self.privet_url['register']['complete'], data='',
        headers=self.headers, user=Constants.USER['EMAIL'])
    # Add the device id from the Cloud Print Service.
    info = self.jparser.Read(response['data'])
    if info['json']:
      for k in info:
        if 'device_id' in k:
          self.id = info[k]
          self.logger.debug('Registered with device id: %s', self.id)
    return self.transport.LogData(response)

  def UnRegister(self, auth_token):
    """Remove device from Google Cloud Service.

    Args:
      auth_token: string, auth token of device owner.
    Returns:
      boolean: True = success, False = errors.
    """
    if self.id:
      delete_url = '%s/delete?printerid=%s' % (Constants.AUTH['URL']['GCP'],
                                               self.id)
      response = self.transport.HTTPReq(delete_url, auth_token=auth_token,
                                        data='')
    else:
      self.logger.warning('Cannot delete device, not registered.')
      return False

    result = self.jparser.Validate(response['data'])
    if result:
      self.logger.debug('Successfully deleted printer from service.')
      self.id = None
      return True
    else:
      self.logger.error('Unable to delete printer from service.')
      return False
