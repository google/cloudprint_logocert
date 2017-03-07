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


A class to hold device attributes.

This class is used by the Cloud Print Logo Certification tool, to hold the
attributes of a device. Before the device attributes are fully populated,
the methods GetDeviceDetails and GetDeviceCDD must be run.
"""

from _config import Constants
from _jsonparser import JsonParser
from _privet import Privet
from _transport import Transport

from _common import Sleep
from _common import PromptUserAction
from json import dumps
from os.path import basename
import requests
import time



class Device(object):
  """The basic device object."""

  def __init__(self, logger, auth_token, gcp, model=None, privet_port=None):
    """Initialize a device object.

    Args:
      logger: initialized logger object.
      auth_token: string, auth_token of authenticated user.
      gcp: initialized GCPService object
      model: string, unique model or name of device.
      privet_port: integer, tcp port devices uses for Privet protocol.
    """
    if model:
      self.model = model
    else:
      self.model = Constants.PRINTER['MODEL']

    self.auth_token = auth_token
    self.logger = logger
    self.ipv4 = Constants.PRINTER['IP']
    if privet_port:
      self.port = privet_port
    else:
      self.port = Constants.PRINTER['PORT']
    self.dev_id = None
    self.name = Constants.PRINTER['NAME']
    self.gcp = gcp
    self.status = None
    self.messages = {}
    self.details = {}
    self.error_state = False
    self.warning_state = False
    self.cdd = {}
    self.supported_types = None
    self.info = None

    self.url = 'http://%s:%s' % (self.ipv4, self.port)
    self.logger.info('Device URL: %s', self.url)
    self.transport = Transport(logger)
    self.jparser = JsonParser(logger)
    self.headers = None
    self.privet = Privet(logger)
    self.privet_url = self.privet.SetPrivetUrls(self.ipv4, self.port)
    self.GetPrivetInfo()


  def GetPrivetInfo(self):
    self.privet_info = {}
    info = self.Info()
    if info is not None:
      for key in info:
        self.privet_info[key] = info[key]
        self.logger.debug('Privet Key: %s', key)
        self.logger.debug('Value: %s', info[key])
        self.logger.debug('--------------------------')
      if 'x-privet-token' in info:
        self.headers = {'X-Privet-Token': str(info['x-privet-token'])}


  def Register(self, msg, user=Constants.USER['EMAIL'], use_token=True,
               no_wait=False, wait_for_user=True):
    """Register device using Privet.
    Args:
      msg: string, the instruction for the user about the registration
                   confirmation dialog on the printer
      user: string, the user to register for
      use_token: boolean, use auth_token if True
      no_wait: boolean, if True, do not wait
      wait_for_user: boolean, if True, wait for user to press UI button
    Returns:
      boolean: True = device registered, False = device not registered.
    Note, devices a required user input to accept or deny a registration
    request, so manual intervention is required.
    """
    if self.StartPrivetRegister(user=user):
      if no_wait:
        print msg
      else:
        PromptUserAction(msg)
      if self.GetPrivetClaimToken(user=user, wait_for_user=wait_for_user):
        auth_token = self.auth_token if use_token else None
        if self.ConfirmRegistration(auth_token):
          self.FinishPrivetRegister()
          return True

    return False


  def GetDeviceCDDLocally(self):
    """Get device cdd and populate device object with the details via privet.

    Args:
      device_id: string, Cloud Print device id.
    Returns:
      boolean: True = cdd details populated, False = cdd details not populated.
    """
    r = requests.get(self.privet_url['capabilities'], headers=self.headers)
    if r is None:
      return False
    response = r.json()

    if 'printer' in response:
      self.cdd['caps'] = {}
      for k in response['printer']:
        self.cdd['caps'][k] = response['printer'][k]
      self.supported_types = [type['content_type'] for type in
                              self.cdd['caps']['supported_content_type']]
      return True
    else:
      self.logger.error('Could not find printers in cdd.')
    return False

  def __parseDeviceDetails(self, printer):
    """Parse through the printer device object and extract information

        Args:
          printer: dict, object containing printer device details."""
    for k in printer:
      if k == 'name':
        self.name =printer[k]
      elif k == 'connectionStatus':
        self.status = printer[k]
      elif k == 'id':
        self.dev_id = printer[k]
      else:
        self.details[k] = printer[k]


  def GetDeviceDetails(self):
    """Get the device details from our management page through the cloud.

    Returns:
      boolean: True = device populated, False = errors.

    This will populate a Device object with device name, status, state messages,
    and device details.
    """
    response = self.gcp.Search(self.name)
    if not response['printers']:
      print ('%s not found as registered printer under the /search gcp api' %
             self.name)
      print 'Update PRINTER["NAME"] in _config.py if misconfigured'
      full_response = self.gcp.Search()
      print "Below is the list of registered printers:"
      for printer in full_response['printers']:
        print printer['name']
      raise

    self.__parseDeviceDetails(response['printers'][0])
    if self.dev_id:
      if self.GetDeviceCDD(self.dev_id):
        self.supported_types = [type['content_type'] for type in
                                self.cdd['caps']['supported_content_type']]
        return True

    return False

  def GetDeviceCDD(self, device_id):
    """Get device cdd and populate device object with the details via the cloud.

    Args:
      device_id: string, Cloud Print device id.
    Returns:
      boolean: True = cdd details populated, False = cdd details not populated.
    """
    info = self.gcp.Printer(device_id)
    if 'printers' in info:
      self.__parseCDD(info['printers'][0])
      if ('num_issues' in self.cdd['uiState'] and
              self.cdd['uiState']['num_issues'] > 0):
        self.error_state = True
      else:
        self.error_state = False
      return True
    else:
      self.logger.error('Could not find printers in cdd.')
    return False


  def __parseCDD(self, printer):
    """Parse the CDD json string into a logical dictionary.

    Args:
      printer: formatted data from /printer interface.
    Returns:
      boolean: True = CDD parsed, False = CDD not parsed.
    """
    for k in printer:
      if k == 'capabilities':
        self.cdd['caps'] = {}
      else:
        self.cdd[k] = printer[k]

    for k in printer['capabilities']['printer']:
      self.cdd['caps'][k] = printer['capabilities']['printer'][k]
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
    Sleep('REG_CANCEL')
    return response['code']

  def StartPrivetRegister(self, user=Constants.USER['EMAIL']):
    """Start a device registration using the Privet protocol.

    Returns:
      boolean: True = success, False = errors.
    """

    self.logger.debug('Registering device %s with Privet', self.ipv4)
    response = self.transport.HTTPReq(
        self.privet_url['register']['start'], data='',
        headers=self.headers, user=user)

    if response is None:
      return False

    self.transport.LogData(response)

    return response['code'] == 200

  def GetPrivetClaimToken(self, user=Constants.USER['EMAIL'],
                          wait_for_user=True):
    """Wait for user interaction with the Printer's UI and get a
       Privet Claim Token.
       Raises EnvironmentError if the printer keeps returning
       'pending_user_action'
    Args:
      user: string, email address to register under.
      wait_for_user: boolean, True if user is expected to interact with printer

    Returns:
      boolean: True = success, False = errors.
    """
    print ('Waiting up to 60 seconds for printer UI interaction '
           'then getting Privet Claim Token.')
    t_end = time.time() + 60;

    while time.time()<t_end:
      response = self.transport.HTTPReq(
          self.privet_url['register']['getClaimToken'], data='',
          headers=self.headers, user=user)
      self.transport.LogData(response)
      if 'token' in response['data']:
        self.claim_token = self.jparser.GetValue(response['data'], key='token')
        self.automated_claim_url = self.jparser.GetValue(
            response['data'], key='automated_claim_url')
        self.claim_url = self.jparser.GetValue(
            response['data'], key='claim_url')
        return True

      if 'error' in response['data']:
        if 'pending_user_action' in response['data']:
          if wait_for_user:
            # Still waiting for user input
            continue
          else:
            print 'getClaimToken() should not return \'pending_user_action\''
            raise EnvironmentError
        else:
          return False
      time.sleep(Constants.SLEEP['POLL'])

    print 'GetPrivetClaimToken() timed out from waiting for printer interaction'
    return False

  def SendClaimToken(self, auth_token=None):
    """Send a claim token to the Cloud Print service.

    Args:
      auth_token: string, auth token of user registering printer.
    Returns:
      boolean: True = success, False = errors.
    """
    if not auth_token:
      auth_token = self.auth_token
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

  def ConfirmRegistration(self, auth_token):
    """Register printer with GCP Service using claim token.

    Returns:
      boolean: True = printer registered, False = printer not registered.
    This method should only be called once self.claim_token is populated.
    """
    if not self.claim_token:
      self.logger.error('No claim token has been  set yet.')
      self.logger.error('Execute GetClaimToken() before this method.')
      return False
    url = '%s/confirm?token=%s' % (Constants.GCP['MGT'], self.claim_token)
    response = self.transport.HTTPReq(url, data='', headers=self.headers,
                                      auth_token=auth_token)
    info = self.jparser.Read(response['data'])
    if 'success' in info and info['success']:
      return True

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
          self.dev_id = info[k]
          self.logger.debug('Registered with device id: %s', self.dev_id)
    return self.transport.LogData(response)

  def UnRegister(self, auth_token):
    """Remove device from Google Cloud Service.

    Args:
      auth_token: string, auth token of device owner.
    Returns:
      boolean: True = success, False = errors.
    """
    if self.dev_id:
      delete_url = '%s/delete?printerid=%s' % (Constants.GCP['MGT'],
                                               self.dev_id)
      response = self.transport.HTTPReq(delete_url, auth_token=auth_token,
                                        data='')
    else:
      self.logger.warning('Cannot delete device, not registered.')
      return False

    result = self.jparser.Validate(response['data'])
    if result:
      self.logger.debug('Successfully deleted printer from service.')
      self.dev_id = None
      return True
    else:
      self.logger.error('Unable to delete printer from service.')
      return False

  def LocalPrint(self, title, content, cjt):
    """Submit a local print job to the printer

        Args:
          title: string, title of the print job
          content: string, url or absolute filepath of the item to print.
          cjt: CloudJobTicket, object that defines the options of the print job
        Returns:
          int, the job id of the local print job that succeeded, else None
        """
    print '\nWait for idle state before starting a local print job'
    success = self.WaitForPrinterState('idle')

    if not success:
      print 'Idle state not observed\n'
      return None

    job_id = self.CreateJob(cjt)
    if job_id is None:
      print 'Error creating a local print job.\n'
      return None

    output = self.SubmitDoc(job_id, title, content)
    if output is None:
      # Cancel the job creation to get back to a normal state
      self.CancelJob(job_id)
      print 'Error printing a local print job.'
      print ('Printer may be in an unstable state if the job isn\'t cancelled '
             'correctly, may need to reboot printer')

    return output

  def CreateJob(self, cjt=None):
    """First step required to submit a local print job.
       Keep trying to obtain the job id for 60 seconds if the printer returns
       busy status

        Args:
          cjt: CloudJobTicket, object that defines the options of the print job
        Returns:
          string, the newly created job_id if successful, else None
        """

    if cjt is None:
      cjt = {}
    else:
      cjt = cjt.val

    url = self.privet_url['createjob']


    print 'Attempt to get a local job id for up to 30 seconds'
    t_end = time.time() + 30

    while time.time() < t_end:
      r = requests.post(url, data=dumps(cjt), headers=self.headers)

      if r is None or requests.codes.ok != r.status_code:
        return None

      res = r.json()

      if 'job_id' not in res:
        if 'error' in res and 'printer_busy' in res['error'].lower():
          print ('Printer is still busy, will try again in %s second(s)' %
                 Constants.SLEEP['POLL'])
          Sleep('POLL')
        else:
          print 'Error: ', res['error']
          return None
      else:
        print 'Got a job id\n'
        return res['job_id']
    return None

  def SubmitDoc(self, job_id, title, content):
    """Second step for printing locally, submit a local print job to the printer

        Args:
          job_id: string, local job id that was returned by /createjob
          title: string, title of the print job
          content: string, url or absolute filepath of the item to print.
        Returns:
          int, the job id of the print job if successful, else None
            """
    name = basename(content)
    with open(content, 'rb') as f:
      content = f.read()

    url = (self.privet_url['submitdoc'] + '?job_id=%s&job_name=%s' %
           (job_id, title))

    content_type = 'image/pwg-raster'

    if content_type not in self.supported_types:
      print ('This printer does not support the following content type: %s' %
             (content_type))
      print 'List of supported types are: ', self.supported_types
      return None

    headers = self.headers  # Get X-Privet_Token
    headers['Content-Type'] = content_type

    r = requests.post(url, data=content, headers=headers)

    if r is None:
      return None

    res = r.json()

    return job_id if 'job_id' in res else None

  def JobState(self, job_id):
    """Optional Api that printers can implement to track job states

        Args:
          job_id: string, local job id

        Returns:
          dict, The response of the API call if succeeded, else None
        """
    url = self.privet_url['jobstate'] + '?job_id=%s' % job_id

    r = requests.get(url, headers=self.headers)

    if r is None or requests.codes.ok != r.status_code:
      return None

    return r.json()


  def Info(self):
    """Make call to the privet/info API to get the latest printer info

      Returns:
        dict, the info object if successful, else None
        """
    response = self.transport.HTTPReq(self.privet_url['info'],
                                      headers=self.privet.headers_empty)
    info = self.jparser.Read(response['data'])
    if not info['json']:
      if response['code']:
        self.logger.debug('HTTP device return code: %s', response['code'])
      if response['headers']:
        self.logger.debug('HTTP Headers:  ')
        for key in response['headers']:
          self.logger.debug('%s: %s', key, response['headers'][key])
      if response['data']:
        self.logger.debug('Data from response: %s', response['data'])
      return None
    else:
      return info


  def WaitForPrinterState(self, state,
                          timeout=Constants.TIMEOUT['PRINTER_STATUS']):
    """Wait until the printer state becomes the specified status

        Args:
          state: string, printer state to wait for
          timeout: integer, number of seconds to wait.
        Returns:
          boolean, True if state is observed within timeout; otherwise, False.
        """
    print '[Configurable timeout] PRINTER_STATUS:'
    print ('Waiting up to %s seconds for the printer to have status: %s' %
           (timeout, state))

    end = time.time() + timeout

    while time.time() < end:
      info = self.Info()
      if info is not None:
        if info['device_state'] == state:
          print 'Device state observed to be: %s' % state
          return True
      Sleep('POLL')

    return False

  def isPrinterRegistered(self):
    """Use the /privet/info interface to see if printer is registered

        Returns:
          boolean, True if registered, False if not registered,
                   None if /privet/info failed
        """
    info = self.Info()
    if info is not None:
        return info['id'] and info['connection_state'] == 'online'
    return None



  def CancelJob(self, job_id):
    #TODO: Posting a mismatch job seems to cancel the created job,
    # find a better way to do this
    url = self.privet_url['submitdoc'] + '?job_id=%s' % (job_id)

    headers = self.headers
    headers['Content-Type'] = 'image/pwg-raster'

    requests.post(url, data=Constants.IMAGES['PDF13'], headers=headers)
