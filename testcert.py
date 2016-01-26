#!/usr/bin/python

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


The main runner for tests used by the Cloud Print Logo Certification tool.

This suite of tests depends on the unittest runner to execute tests. It will log
results and debug information into a log file. In order for these tests to
execute properly, WebDriver (ChromeDriver) must be installed.

Before executing this program, edit _config.py and put in the proper values for
the printer being tested, and the test accounts that you are using. For the
primary test account, you need to add some OAuth2 tokens, a Client ID and a
Client Secret. Consult the README file for more details about setting up these
tokens and other needed variables in _config.py.

When testcert.py executes, some of the tests will require manual intervention,
therefore watch the output of the script while it's running.

test_id corresponds to an internal database used by Google, so don't change
those IDs. These IDs are used when submitting test results to our database.
"""

import optparse
import time
import unittest

import _chrome
import _chromedriver
import _cloudprintmgr
from _common import ReadJsonFile
from _common import WriteJsonFile
from _config import Constants
from _device import Device
import _log
import _mdns
import _oauth2
import _sheets
from _transport import Transport


def _ParseArgs():
  """Parse command line options."""

  parser = optparse.OptionParser()

  parser.add_option('--autorun',
                    help='Set if tests need manual input [default: %default]',
                    default=Constants.AUTOMODE,
                    dest='autorun')
  parser.add_option('--debug',
                    help='Specify debug log level [default: %default]',
                    default='info',
                    type='choice',
                    choices=['debug', 'info', 'warning', 'error', 'critical'],
                    dest='debug')
  parser.add_option('--email',
                    help='Email account to use [default: %default]',
                    default=Constants.USER['EMAIL'],
                    dest='email')
  parser.add_option('--loadtime',
                    help='Seconds for web pages to load [default: %default]',
                    default=10,
                    dest='loadtime')
  parser.add_option('--logdir',
                    help='Relative directory for logfiles [default: %default]',
                    default=Constants.LOGFILES,
                    dest='logdir')
  parser.add_option('--passwd',
                    help='Email account password [default: %default]',
                    default=Constants.USER['PW'],
                    dest='passwd')
  parser.add_option('--printer',
                    help='Name of printer [default: %default]',
                    default=Constants.PRINTER['MODEL'],
                    dest='printer')
  parser.add_option('--stdout',
                    help='Send output to stdout [default: %default]',
                    default=True,
                    dest='stdout')

  return parser.parse_args()
# The setUpModule will run one time, before any of the tests are run. One main
# Chrome session will be used to execute most of the tests. The global
# keyword must be used in order to give all of the test classes access to
# these objects. This approach is used to eliminate the need for initializing
# all of these objects for each and every test class.
#
# If Google Spreadsheets are used to hold the test results, then a separate
# tab will be opened to display this spreadsheet.


def setUpModule():
  # pylint: disable=global-variable-undefined
  global chrome
  global chromedriver
  global gcpmgr
  global logger
  global transport
  global device

  options, unused_args = _ParseArgs()
  data_dir = options.email.split('@')[0]
  logger = _log.GetLogger('LogoCert', logdir=options.logdir,
                          loglevel=options.debug, stdout=options.stdout)
  chromedriver = _chromedriver.ChromeDriver(data_dir, options.loadtime)
  chrome = _chrome.Chrome(chromedriver)
  chrome.SignIn(options.email, options.passwd)
  CheckCredentials()
  gcpmgr = _cloudprintmgr.CloudPrintMgr(chromedriver)
  device = Device(chromedriver)
  transport = Transport()
  time.sleep(2)

  if Constants.TEST['SPREADSHEET']:
    global sheet
    sheet = _sheets.SheetMgr(chromedriver, Constants)
    sheet.MakeHeaders()
  # pylint: enable=global-variable-undefined


def tearDownModule():
  chromedriver.CloseChrome()


def CheckCredentials():
  """Check for credentials."""
  if 'REFRESH' in Constants.AUTH:
    RefreshToken()
  else:
    credentials = ReadJsonFile(Constants.AUTH['CRED_FILE'])
    if credentials:
      if 'refresh_token' in credentials:
        Constants.AUTH['REFRESH'] = credentials['refresh_token']
      if 'access_token' in credentials:
        Constants.AUTH['ACCESS'] = credentials['access_token']
      RefreshToken()
    else:
      GetNewTokens()


def RefreshToken():
  """Get a new access token with an existing refresh token."""
  response = _oauth2.RefreshToken()
  # If there is an error in the response, it means the current access token
  # has not yet expired.
  if 'access_token' in response:
    logger.info('Got new access token.')
    Constants.AUTH['ACCESS'] = response['access_token']
  else:
    logger.info('Using current access token.')


def GetNewTokens():
  """Get all new tokens for this user account.

  This process is described in detail here:
  https://developers.google.com/api-client-library/python/guide/aaa_oauth

  If there is a problem with the automation authorizing access, then you
  may need to manually access the permit_url while logged in as the test user
  you are using for this automation.
  """
  auth_code = None
  permit_url = _oauth2.GenerateUrl()
  chromedriver.driver.get(permit_url)
  #  This may take awhile, so wait for the page to load.
  time.sleep(5)
  approve = chromedriver.FindID('submit_approve_access')
  chromedriver.ClickElement(approve)
  code = chromedriver.FindID('code')
  auth_code = code.get_attribute('value')

  if auth_code:
    creds = _oauth2.GetTokens(auth_code)
    if 'refresh_token' in creds:
      Constants.AUTH['REFRESH'] = creds['refresh_token']
    if 'access_token' in creds:
      Constants.AUTH['ACCESS'] = creds['access_token']
    WriteJsonFile(Constants.AUTH['CRED_FILE'], creds)
  else:
    logger.error('Error getting authorization code.')


class LogoCert(unittest.TestCase):
  """Base Class to drive Logo Certification tests."""

  @classmethod
  def setUpClass(cls):
    options, unused_args = _ParseArgs()
    cls.loadtime = options.loadtime
    cls.username = options.email
    cls.pw = options.passwd
    cls.autorun = options.autorun
    cls.printer = options.printer

    if Constants.CAPS['COLOR']:
      cls.color = 'Color'
    else:
      cls.color = 'Monochrome'
    time.sleep(2)

  def ManualPass(self, test_id, test_name, print_test=True):
    """Take manual input to determine if a test passes.

    Args:
      test_id: integer, testid in TestTracker database.
      test_name: string, name of test.
      print_test: boolean, True = print test, False = not print test.
    Returns:
      boolean: True = Pass, False = Fail.
    If self.autorun is set to true, then this method will pause and return True.
    """
    if self.autorun:
      if print_test:
        notes = 'Manually examine printout to verify correctness.'
      else:
        notes = 'Manually verify the test produced the expected result.'
      self.LogTest(test_id, test_name, 'Passed', notes)
      time.sleep(5)
      return True
    print 'Did the test produce the expected result?'
    result = raw_input('Enter "y" or "n"\n')
    try:
      self.assertEqual(result, 'y')
    except AssertionError:
      print 'Additional notes for test failure: \n'
      notes = raw_input('Hit return when finished\n')
      self.LogTest(test_id, test_name, 'Failed', notes)
      return False
    else:
      self.LogTest(test_id, test_name, 'Passed')
      return True

  def LogTest(self, test_id, test_name, result, notes=None):
    """Log a test result.

    Args:
      test_id: integer, test id in the TestTracker application.
      test_name: string, name of the test.
      result: string, ["Passed", "Failed", "Blocked", "Skipped", "Not Run"]
      notes: string, notes to include with the test result.
    """
    logger.info('test_id: %s: %s', test_id, result)
    logger.info('%s: %s', test_id, test_name)
    if notes:
      logger.info('%s: %s', test_id, notes)
    else:
      notes = ''
    if Constants.TEST['SPREADSHEET']:
      row = [str(test_id), test_name, result, notes]
      sheet.AddRow(row)

  def SignIn(self):
    chrome.SignIn(self.username, self.pw)

  @classmethod
  def GetDeviceDetails(cls):
    device.GetDeviceDetails()
    if not device.name:
      logger.error('Error finding device in GCP MGT page.')
      logger.error('Check printer model in _config file.')
      raise unittest.SkipTest('Could not find device on GCP MGT page.')
    else:
      logger.info('Printer name: %s', device.name)
      logger.info('Printer status: %s', device.status)
      for k in device.details:
        logger.info(k)
        logger.info(device.details[k])
        logger.info('===============================')
      device.GetDeviceCDD(device.details['Printer ID'])
      for k in device.cdd:
        logger.info(k)
        logger.info(device.cdd[k])
        logger.info('===============================')


class SystemUnderTest(LogoCert):
  """Record details about the system under test and test environment."""

  def testRecordTestEnv(self):
    """Record test environment details."""
    test_id = '5e5e44cd-4e37-4f16-b1ec-1874912c7449'
    test_name = 'testRecordTestEnv'
    notes = 'Android: %s\n' % Constants.TESTENV['ANDROID']
    notes += 'Chrome: %s\n' % Constants.TESTENV['CHROME']
    notes += 'Tablet: %s\n' % Constants.TESTENV['TABLET']
    notes += 'ChromeDriver: %s\n' % Constants.TESTENV['CHROMEDRIVER']

    self.LogTest(test_id, test_name, 'Skipped', notes)

  def testRecordManufacturer(self):
    """Record device manufacturer."""
    test_id = '9b9d158d-da11-4b6b-9181-dafcbd8b49c5'
    test_name = 'testRecordManufacturer'
    notes = 'Manufacturer: %s' % Constants.PRINTER['MANUFACTURER']

    self.LogTest(test_id, test_name, 'Skipped', notes)

  def testRecordModel(self):
    """Record device model number."""
    test_id = '9627ef75-0a15-422b-9d90-a1012d03b1dc'
    test_name = 'testRecordModel'
    notes = 'Model: %s' % Constants.PRINTER['MODEL']

    self.LogTest(test_id, test_name, 'Skipped', notes)

  def testRecordDeviceStatus(self):
    """Record device status: released, internal, prototype, unknown."""
    test_id = '62f0e328-52e2-4077-bffe-1bf67b160f7a'
    test_name = 'testRecordDeviceStatus'
    notes = 'Device Status: %s' % Constants.PRINTER['STATUS']

    self.LogTest(test_id, test_name, 'Skipped', notes)

  def testRecordFirmware(self):
    """Record device firmware version reported by device UI."""
    test_id = '74bd2b38-35ee-48fa-aa92-ffc93b1357fe'
    test_name = 'testRecordFirmware'
    notes = 'Firmware: %s' % Constants.PRINTER['FIRMWARE']

    self.LogTest(test_id, test_name, 'Skipped', notes)

  def testRecordSerialNumber(self):
    """Record device serial number."""
    test_id = '2feb2c3d-e02a-4c9e-b23a-9b9558591924'
    test_name = 'testRecordSerialNumber'
    notes = 'Serial Number: %s' % Constants.PRINTER['SERIAL']

    self.LogTest(test_id, test_name, 'Skipped', notes)


class Privet(LogoCert):
  """Verify device integrates correctly with the Privet protocol.

  These tests should be run before a device is registered.
  """

  def testPrivetInfoAPI(self):
    """Verify device responds to PrivetInfo API requests."""
    test_id = '612051fb-f156-4846-8924-e62f70273643'
    test_name = 'testPrivetInfoAPI'
    # When a device object is initialized, it sends a request to the privet
    # info API, so all of the needed information should already be set.
    try:
      self.assertIn('x-privet-token', device.privet_info)
    except AssertionError:
      notes = 'No x-privet-token found. Error in privet info API.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'X-Privet-Token: %s' % device.privet_info['x-privet-token']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoAPIManufacturer(self):
    """Verify device PrivetInfo API contains manufacturer field."""
    test_id = '0da3de50-2541-4585-8314-d3593be7a2d9'
    test_name = 'testPrivetInfoAPIManufacturer'
    # When a device object is initialized, it sends a request to the privet
    # info API, so all of the needed information should already be set.
    try:
      self.assertIn('manufacturer', device.privet_info)
    except AssertionError:
      notes = 'manufacturer not found in privet info.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Manufacturer: %s' % device.privet_info['manufacturer']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoAPIModel(self):
    """Verify device PrivetInfo API contains model field."""
    test_id = 'd2725e0d-033a-45b2-b528-cb00f8729e5b'
    test_name = 'testPrivetInfoAPIModel'
    # When a device object is initialized, it sends a request to the privet
    # info API, so all of the needed information should already be set.
    try:
      self.assertIn('model', device.privet_info)
    except AssertionError:
      notes = 'model not found in privet info.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Model: %s' % device.privet_info['model']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoAPIFirmware(self):
    """Verify device PrivetInfo API contains firmware field."""
    test_id = '9ab29ed3-cbed-458e-9cd7-0021c1da37d2'
    test_name = 'testPrivetInfoAPIFirmware'
    # When a device object is initialized, it sends a request to the privet
    # info API, so all of the needed information should already be set.
    try:
      self.assertIn('firmware', device.privet_info)
    except AssertionError:
      notes = 'firmware not found in privet info.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Firmware: %s' % device.privet_info['firmware']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoAPIUpdateUrl(self):
    """Verify device PrivetInfo API contains update_url field."""
    test_id = 'd7f67d75-9f9d-49ad-b3b2-5557c8c51470'
    test_name = 'testPrivetInfoAPIUpdateUrl'
    # When a device object is initialized, it sends a request to the privet
    # info API, so all of the needed information should already be set.
    try:
      self.assertIn('update_url', device.privet_info)
    except AssertionError:
      notes = 'update_url not found in privet info.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'update_url: %s' % device.privet_info['update_url']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoAPIVersion(self):
    """Verify device PrivetInfo API contains version field."""
    test_id = 'daef86f2-f979-4960-8d57-677ce2b237d7'
    test_name = 'testPrivetInfoAPIVersion'
    # When a device object is initialized, it sends a request to the privet
    # info API, so all of the needed information should already be set.
    valid_versions = ['1.0', '1.1', '1.5', '2.0']
    try:
      self.assertIn('version', device.privet_info)
    except AssertionError:
      notes = 'version not found in privet info.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertIn(device.privet_info['version'], valid_versions)
      except AssertionError:
        notes = 'Incorrect GCP Version in privetinfo: %s' % (
            device.privet_info['version'])
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Version: %s' % device.privet_info['version']
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoDeviceState(self):
    """Verify device PrivetInfo API contains DeviceState and valid value."""
    test_id = '3d0fdb69-d14c-4628-a45d-54048465f741'
    test_name = 'testPrivetInfoDeviceState'
    valid_states = ['idle', 'processing', 'stopped']
    try:
      self.assertIn('device_state', device.privet_info)
    except AssertionError:
      notes = 'device_state not found in privet info.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertIn(device.privet_info['device_state'], valid_states)
      except AssertionError:
        notes = 'Incorrect device_state in privet info: %s' % (
            device.privet_info['device_state'])
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Device state: %s' % device.privet_info['device_state']
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoConnectionState(self):
    """Verify device PrivetInfo contains ConnectionState and valid value."""
    test_id = '2f4b5912-fa44-4e37-b4a5-01cd2ea7fcfc'
    test_name = 'testPrivetInfoConnectionState'
    valid_states = ['online', 'offline', 'connecting', 'not-configured']
    try:
      self.assertIn('connection_state', device.privet_info)
    except AssertionError:
      notes = 'connection_state not found in privet info.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertIn(device.privet_info['connection_state'], valid_states)
      except AssertionError:
        notes = 'Incorrect connection_state in privet info: %s' % (
            device.privet_info['connection_state'])
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Connection state: %s' % device.privet_info['connection_state']
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetAccessTokenAPI(self):
    """Verify unregistered device Privet AccessToken API returns correct rc."""
    test_id = '74b0548c-5932-4aaa-a363-56dd9d44268b'
    test_name = 'testPrivetAccessTokenAPI'
    api = 'accesstoken'
    if Constants.CAPS['LOCAL_PRINT']:
      return_code = 200
    else:
      return_code = 404
    response = transport.HTTPReq(device.privet_url[api], headers=device.headers)
    try:
      self.assertIsNotNone(response['code'])
    except AssertionError:
      notes = 'No response received from %s' % device.privet_url[api]
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertEqual(response['code'], return_code)
      except AssertionError:
        notes = 'Incorrect return code, found %d' % response['code']
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = '%s returned response code %d' % (device.privet_url[api],
                                                  response['code'])
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetCapsAPI(self):
    """Verify unregistered device Privet Capabilities API returns correct rc."""
    test_id = '82bd4d7d-e70b-45fb-9ecb-41f267ef9b24'
    test_name = 'testPrivetCapsAPI'
    api = 'capabilities'
    if Constants.CAPS['LOCAL_PRINT']:
      return_code = 200
    else:
      return_code = 404
    response = transport.HTTPReq(device.privet_url[api], headers=device.headers)
    try:
      self.assertIsNotNone(response['code'])
    except AssertionError:
      notes = 'No response received from %s' % device.privet_url[api]
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertEqual(response['code'], return_code)
      except AssertionError:
        notes = 'Incorrect return code, found %d' % response['code']
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = '%s returned code %d' % (device.privet_url[api],
                                         response['code'])
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetPrinterAPI(self):
    """Verify unregistered device Privet Printer API returns correct rc."""
    test_id = 'c6e56ee1-eb55-478b-a495-dbdfeb7fe1ae'
    test_name = 'testPrivetPrinterAPI'
    api = 'printer'
    if Constants.CAPS['LOCAL_PRINT']:
      return_code = 200
    else:
      return_code = 404
    response = transport.HTTPReq(device.privet_url[api], headers=device.headers)
    try:
      self.assertIsNotNone(response['code'])
    except AssertionError:
      notes = 'No response received from %s' % device.privet_url[api]
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertEqual(response['code'], return_code)
      except AssertionError:
        notes = 'Incorrect return code, found %d' % response['code']
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = '%s returned code %d' % (device.privet_url[api],
                                         response['code'])
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetUnknownURL(self):
    """Verify device returns 404 return code for unknown url requests."""
    test_id = 'caf2f4e7-df0d-4093-8303-73eff5ab9024'
    test_name = 'testPrivetUnknownURL'
    response = transport.HTTPReq(device.privet_url['INVALID'],
                                 headers=device.headers)
    try:
      self.assertIsNotNone(response['code'])
    except AssertionError:
      notes = 'No response code received.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertEqual(response['code'], 404)
      except AssertionError:
        notes = 'Wrong return code received. Received %d' % response['code']
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Received correct return code: %d' % response['code']
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetRegisterAPI(self):
    """Verify unregistered device exposes register API."""
    test_id = '48f09590-03b1-4068-a902-c21290026247'
    test_name = 'testPrivetRegisterAPI'
    response = transport.HTTPReq(
        device.privet_url['register']['start'], data='',
        headers=device.headers, user=self.username)
    transport.HTTPReq(
        device.privet_url['register']['cancel'], data='',
        headers=device.headers, user=self.username)
    try:
      self.assertIsNotNone(response['code'])
    except AssertionError:
      notes = 'No response received.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertEqual(response['code'], 200)
      except AssertionError:
        notes = 'Received return code: %d' % response['code']
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Received return code: %s' % response['code']
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetRegistrationInvalidParam(self):
    """Verify device return error if invalid registration param given."""
    test_id = 'fec798b2-ed5f-44ac-8752-e44fd47462e2'
    test_name = 'testPrivetRegistrationInvalidParam'
    response = transport.HTTPReq(
        device.privet_url['register']['invalid'], data='',
        headers=device.headers, user=self.username)
    try:
      self.assertIsNotNone(response['data'])
    except AssertionError:
      notes = 'No response received.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertIn('error', response['data'])
        self.assertIn('invalid', response['data'])
      except AssertionError:
        notes = 'Response from invalid registration params: %s' % (
            response['data'])
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Received correct error: %s' % response['data']
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoAPIEmptyToken(self):
    """Verify device returns code 200 if Privet Token is empty."""
    test_id = '9cce6158-7b68-42b3-94b2-9bacadac07c9'
    test_name = 'testPrivetInfoAPIEmptyToken'
    response = transport.HTTPReq(device.privet_url['info'],
                                 headers=device.privet.headers_empty)
    try:
      self.assertIsNotNone(response['code'])
    except AssertionError:
      notes = 'No reponse code received.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertEqual(response['code'], 200)
      except AssertionError:
        notes = 'Return code received: %d' % response['code']
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Return code: %d' % response['code']
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoAPIInvalidToken(self):
    """Verify device returns code 200 if Privet Token is invalid."""
    test_id = 'f568feee-4693-4643-a61a-73a705288808'
    test_name = 'testPrivetInfoAPIInvalidToken'
    response = transport.HTTPReq(device.privet_url['info'],
                                 headers=device.privet.headers_invalid)
    try:
      self.assertIsNotNone(response['code'])
    except AssertionError:
      notes = 'No reponse code received.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertEqual(response['code'], 200)
      except AssertionError:
        notes = 'Return code received: %d' % response['code']
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Return code: %d' % response['code']
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoAPIMissingToken(self):
    """Verify device returns code 400 if Privet Token is missing."""
    test_id = '271a2089-be2e-4237-b0c1-e64f4e636c35'
    test_name = 'testPrivetInfoAPIMissingToken'
    response = transport.HTTPReq(device.privet_url['info'],
                                 headers=device.privet.headers_missing)
    try:
      self.assertIsNotNone(response['code'])
    except AssertionError:
      notes = 'No reponse code received.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertEqual(response['code'], 400)
      except AssertionError:
        notes = 'Return code received: %d' % response['code']
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Return code: %d' % response['code']
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testDeviceRegistrationInvalidClaimToken(self):
    """Verify a device will not register if the claim token in invalid."""
    test_id = 'a48518b0-bc96-480b-a8f2-f26cbb42e1b8'
    test_name = 'testDeviceRegistrationInvalidClaimToken'
    try:
      self.assertTrue(device.StartPrivetRegister())
    except AssertionError:
      notes = 'Error starting privet registration.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      try:
        print 'Accept the registration request on the device.'
        raw_input('Select enter once registration accepted.')
        try:
          self.assertTrue(device.GetPrivetClaimToken())
        except AssertionError:
          notes = 'Error getting claim token.'
          self.LogTest(test_id, test_name, 'Blocked', notes)
          raise
        else:
          device.automated_claim_url = (
              'https://www.google.com/cloudprint/confirm?token=INVALID')
          try:
            self.assertFalse(device.SendClaimToken(Constants.AUTH['ACCESS']))
          except AssertionError:
            notes = 'Device accepted invalid claim token.'
            self.LogTest(test_id, test_name, 'Failed', notes)
            raise
          else:
            notes = 'Device did not accept invalid claim token.'
            self.LogTest(test_id, test_name, 'Passed', notes)
      finally:
        device.CancelRegistration()
        time.sleep(10)

  def testDeviceRegistrationInvalidUserAuthToken(self):
    """Verify a device will not register is user auth token is invalid."""
    test_id = 'da3d4ce4-5b81-4bb4-a487-7c8e92b552c6'
    test_name = 'testDeviceRegistrationInvalidUserAuthToken'
    try:
      self.assertTrue(device.StartPrivetRegister())
    except AssertionError:
      notes = 'Error starting privet registration.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      try:
        print 'Accept the registration request on the device.'
        print 'Note: some printers may not show a registration request.'
        raw_input('Select enter once registration is accepted.')
        try:
          self.assertTrue(device.GetPrivetClaimToken())
        except AssertionError:
          notes = 'Error getting claim token.'
          self.LogTest(test_id, test_name, 'Blocked', notes)
          raise
        else:
          try:
            self.assertFalse(device.SendClaimToken('INVALID_USER_AUTH_TOKEN'))
          except AssertionError:
            notes = 'Claim token accepted with invalid User Auth Token.'
            self.LogTest(test_id, test_name, 'Failed', notes)
            raise
          else:
            notes = 'Claim token not accepted with invalid user auth token.'
            self.LogTest(test_id, test_name, 'Passed', notes)
      finally:
        device.CancelRegistration()
        time.sleep(10)


class Printer(LogoCert):
  """Verify printer provides necessary details."""

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass()
    LogoCert.GetDeviceDetails()

  def testPrinterName(self):
    """Verify printer provides a name."""
    test_id = '79f45999-b9e7-4f95-8992-79c06eaa1b76'
    test_name = 'testPrinterName'
    try:
      self.assertIsNotNone(device.name)
    except AssertionError:
      notes = 'No printer name found.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      logger.info('Printer name found in details.')
    try:
      self.assertIn(Constants.PRINTER['MODEL'], device.name)
    except AssertionError:
      notes = 'Model not in name. Found %s' % device.name
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('name', device.cdd)
    except AssertionError:
      notes = 'Printer CDD missing printer name.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      logger.info('Printer name found in CDD.')
    try:
      self.assertIn(Constants.PRINTER['MODEL'], device.cdd['name'])
    except AssertionError:
      notes = 'Model not in name. Found %s in CDD' % device.cdd['name']
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Printer name: %s' % device.name
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterStatus(self):
    """Verify printer has online status."""
    test_id = 'f04dfb47-5745-498b-b366-c79d37536904'
    test_name = 'testPrinterStatus'
    try:
      self.assertIsNotNone(device.status)
    except AssertionError:
      notes = 'Device has no status.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('online', device.status)
    except AssertionError:
      notes = 'Device is not online. Status: %s' % device.status
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Status: %s' % device.status
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterModel(self):
    """Verify printer provides a model string."""
    test_id = '145f1c07-0e9d-4a5e-ae17-ff31f62c94e3'
    test_name = 'testPrinterModel'
    try:
      self.assertIn('Model', device.details)
    except AssertionError:
      notes = 'Model is missing from the printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn(Constants.PRINTER['MODEL'], device.details['Model'])
    except AssertionError:
      notes = 'Model incorrect, printer details: %s' % device.details['Model']
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('model', device.cdd)
    except AssertionError:
      notes = 'Model is missing from the printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn(Constants.PRINTER['MODEL'], device.cdd['model'])
    except AssertionError:
      notes = 'Printer model has unexpected value. Found %s' % (
          device.cdd['model'])
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Model: %s' % device.details['Model']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterManufacturer(self):
    """Verify printer provides a manufacturer string."""
    test_id = '68134ba3-5a05-4a77-82ca-b06ae6195cd8'
    test_name = 'testPrinterManufacturer'
    try:
      self.assertIn('Manufacturer', device.details)
    except AssertionError:
      notes = 'Manufacturer in not set in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn(Constants.PRINTER['MANUFACTURER'],
                    device.details['Manufacturer'])
    except AssertionError:
      notes = 'Manufacturer is not in printer details. Found %s' % (
          device.details['Manufacturer'])
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('manufacturer', device.cdd)
    except AssertionError:
      notes = 'Manufacturer is not set in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn(Constants.PRINTER['MANUFACTURER'],
                    device.cdd['manufacturer'])
    except AssertionError:
      notes = 'Manufacturer not found in printer CDD. Found %s' % (
          device.cdd['manufacturer'])
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Manufacturer: %s' % device.details['Manufacturer']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterSerialNumber(self):
    """Verify printer provides a serial number."""
    test_id = '3996db1d-93ea-4f4c-b70c-dfd9355d5e5d'
    test_name = 'testPrinterSerialNumber'
    try:
      self.assertIn('Serial Number', device.details)
    except AssertionError:
      notes = 'Serial number not found in device details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(device.details['Serial Number']), 1)
    except AssertionError:
      notes = 'Serial number does is not valid number.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Serial Number: %s' % device.details['Serial Number']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterGCPVersion(self):
    """Verify printer provides GCP Version supported."""
    test_id = '7a8ec212-52d2-441d-8e18-383ac850f567'
    test_name = 'testPrinterGCPVersion'
    try:
      self.assertIn('Google Cloud Print Version', device.details)
    except AssertionError:
      notes = 'GCP Version not found in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertEqual('2.0', device.details['Google Cloud Print Version'])
    except AssertionError:
      notes = 'Version 2.0 not found in GCP Version support. Found %s' % (
          device.details['Google Cloud Print Version'])
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('gcpVersion', device.cdd)
    except AssertionError:
      notes = 'GCP Version not found in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertEqual('2.0', device.cdd['gcpVersion'])
    except AssertionError:
      notes = 'Version 2.0 not found in GCP Version. Found %s' % (
          device.cdd['gcpVersion'])
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'GCP Version: %s' % device.details['Google Cloud Print Version']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterFirmwareVersion(self):
    """Verify printer provides a firmware version."""
    test_id = '96b2fc8d-708d-4be8-b439-7fec563c44d9'
    test_name = 'testPrinterFirmwareVersion'
    try:
      self.assertIn('Firmware Version', device.details)
    except AssertionError:
      notes = 'Firmware version is missing in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(device.details['Firmware Version']), 1)
    except AssertionError:
      notes = 'Firmware version is not correctly identified.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('firmware', device.cdd)
    except AssertionError:
      notes = 'Firmware version is missing in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(device.cdd['firmware']), 1)
    except AssertionError:
      notes = 'Firmware version is not correctly identified in CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Firmware version: %s' % device.details['Firmware Version']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterType(self):
    """Verify printer provides a type."""
    test_id = 'f4fb09a4-527b-4fa7-8629-0171037db113'
    test_name = 'testPrinterType'
    try:
      self.assertIn('Printer Type', device.details)
    except AssertionError:
      notes = 'Printer Type not found in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('Cloud Ready Printer', device.details['Printer Type'])
    except AssertionError:
      notes = 'Incorrect Printer Type in details. Found %s' % (
          device.details['PrinterType'])
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('type', device.cdd)
    except AssertionError:
      notes = 'Printer Type not found in printer CDD'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('GOOGLE', device.cdd['type'])
    except AssertionError:
      notes = 'Incorrect Printer Type in CDD. Found %s' % device.cdd['type']
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Printer Type: %s' % device.details['Printer Type']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterFirmwareUpdateUrl(self):
    """Verify printer provides a firmware update URL."""
    test_id = '27a06940-2f82-4550-8231-69615aa516c8'
    test_name = 'testPrinterFirmwareUpdateUrl'
    try:
      self.assertIn('Firmware Update URL', device.details)
    except AssertionError:
      notes = 'Firmware update url not found in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(
          device.details['Firmware Update URL']), 10)
    except AssertionError:
      notes = 'Firmware Update URL is not valid in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('updateUrl', device.cdd)
    except AssertionError:
      notes = 'Firmware update Url not found in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(device.cdd['updateUrl']), 10)
    except AssertionError:
      notes = 'Firmware Update URL is not valid in CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Firmware Update URL: %s' % (
          device.details['Firmware Update URL'])
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterProxy(self):
    """Verify that printer provides a proxy."""
    test_id = 'd01c84fd-6310-47f0-a464-60997a8e3d68'
    test_name = 'testPrinterProxy'
    try:
      self.assertIn('Proxy', device.details)
    except AssertionError:
      notes = 'Proxy not found in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(device.details['Proxy']), 1)
    except AssertionError:
      notes = 'Proxy is not valid value.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('proxy', device.cdd)
    except AssertionError:
      notes = 'Proxy not found in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(device.cdd['proxy']), 1)
    except AssertionError:
      notes = 'Proxy is not valid value.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Printer Proxy: %s' % device.details['Proxy']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testSetupUrl(self):
    """Verify the printer provides a setup URL."""
    test_id = 'd03c034d-2deb-42d9-a6fd-1685c2472e97'
    test_name = 'testSetupUrl'
    try:
      self.assertIn('setupUrl', device.cdd)
    except AssertionError:
      notes = 'Setup URL not found in CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(device.cdd['setupUrl']), 10)
    except AssertionError:
      notes = 'Setup URL is not a valid. Found %s' % device.cdd['setupUrl']
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Setup URL: %s' % device.cdd['setupUrl']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterID(self):
    """Verify Printer has a PrinterID."""
    test_id = '5bc5d513-3a1f-441a-8acd-d007fe0e0e35'
    test_name = 'testPrinterID'
    try:
      self.assertIn('Printer ID', device.details)
    except AssertionError:
      notes = 'Printer ID not found in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(device.details['Printer ID']), 10)
    except AssertionError:
      notes = 'Printer ID is not valid in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('id', device.cdd)
    except AssertionError:
      notes = 'Printer ID not found in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(device.cdd['id']), 10)
    except AssertionError:
      notes = 'Printer ID is not valid in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Printer ID: %s' % device.details['Printer ID']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testLocalSettings(self):
    """Verify the printer contains local settings."""
    test_id = 'cede3eec-41fb-43de-b1f1-76d17443b6f3'
    test_name = 'testLocalSettings'
    try:
      self.assertIn('local_settings', device.cdd)
    except AssertionError:
      notes = 'local_settings not found in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('current', device.cdd['local_settings'])
    except AssertionError:
      notes = 'No current settings found in local_settings.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Local settings: %s' % device.cdd['local_settings']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCaps(self):
    """Verify the printer contains capabilities."""
    test_id = '1977ab77-27af-4702-a6f3-5b66fc1b5720'
    test_name = 'testCaps'
    try:
      self.assertIn('caps', device.cdd)
    except AssertionError:
      notes = 'No capabilities found in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(device.cdd['caps']), 10)
    except AssertionError:
      notes = 'Capabilities does not have required entries.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.LogTest(test_id, test_name, 'Passed')

  def testUuid(self):
    """Verify the printer contains a UUID."""
    test_id = 'e53df4c2-d208-41d0-bb62-ec6be6ebac9f'
    test_name = 'testUuid'
    try:
      self.assertIn('uuid', device.cdd)
    except AssertionError:
      notes = 'uuid not found in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(device.cdd['uuid']), 1)
    except AssertionError:
      notes = 'uuid is not a valid value.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'UUID: %s' % device.cdd['uuid']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testDefaultDisplayName(self):
    """Verify Default Display Name is present."""
    test_id = '1cb52261-cf01-45ed-b447-8ec8902b36f2'
    test_name = 'testDefaultDisplayName'
    try:
      self.assertIn('defaultDisplayName', device.cdd)
    except AssertionError:
      notes = 'defaultDisplayName not found in printer CDD'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.LogTest(test_id, test_name, 'Passed')

  def testCapsSupportedContentType(self):
    """Verify supported_content_type contains needed types."""
    test_id = 'aa7c157e-bd0a-4048-a8a9-88ce3e9a96b8'
    test_name = 'testCapsSupportedContentType'
    try:
      self.assertIn('supported_content_type', device.cdd['caps'])
    except AssertionError:
      notes = 'supported_content_type missing from printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    content_types = []
    for item in device.cdd['caps']['supported_content_type']:
      for k in item:
        if k == 'content_type':
          content_types.append(item[k])
    try:
      self.assertIn('image/pwg-raster', content_types)
    except AssertionError:
      s = 'image/pwg-raster not found in supported content types.'
      notes = s + '\nFound: %s' % content_types
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Supported content types: %s' % (
          device.cdd['caps']['supported_content_type'])
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsPwgRasterConfig(self):
    """Verify printer CDD contains a pwg_raster_config parameter."""
    test_id = 'e3565806-2320-48ef-8eab-2f48fbcffc33'
    test_name = 'testCapsPwgRasterConfig'
    try:
      self.assertIn('pwg_raster_config', device.cdd['caps'])
    except AssertionError:
      notes = 'pwg_raster_config parameter not found in printer cdd.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'pwg_raster_config: %s' % (
          device.cdd['caps']['pwg_raster_config'])
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsInputTrayUnit(self):
    """Verify input_tray_unit is in printer capabilities."""
    test_id = 'e10b7314-fc04-4a4a-ae59-8bf4a3ae165d'
    test_name = 'testCapsInputTrayUnit'
    try:
      self.assertIn('input_tray_unit', device.cdd['caps'])
    except AssertionError:
      notes = 'input_tray_unit not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'input_tray_unit: %s' % device.cdd['caps']['input_tray_unit']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsOutputBinUnit(self):
    """Verify output_bin_unit is in printer capabilities."""
    test_id = '0f329dba-75c3-45f0-a3a1-4d63f5d195b0'
    test_name = 'testCapsOutputBinUnit'
    try:
      self.assertIn('output_bin_unit', device.cdd['caps'])
    except AssertionError:
      notes = 'output_bin_unit not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'output_bin_unit: %s' % device.cdd['caps']['output_bin_unit']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsMarker(self):
    """Verify marker is in printer capabilities."""
    test_id = '35005c07-3b18-48b2-a3a2-20fe78bedff2'
    test_name = 'testCapsMarker'
    try:
      self.assertIn('marker', device.cdd['caps'])
    except AssertionError:
      notes = 'marker not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'marker: %s' % device.cdd['caps']['marker']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsCover(self):
    """Verify cover is in printer capabilities."""
    test_id = 'c5564d8b-d811-4510-b031-b761bb094631'
    test_name = 'testCapsCover'
    try:
      self.assertIn('cover', device.cdd['caps'])
    except AssertionError:
      notes = 'cover not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'cover: %s' % device.cdd['caps']['cover']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsColor(self):
    """Verify color is in printer capabilities."""
    test_id = '01bd068d-0b8f-41a4-82ea-39ef5fb09994'
    test_name = 'testCapsColor'
    try:
      self.assertIn('color', device.cdd['caps'])
    except AssertionError:
      notes = 'color not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'color: %s' % device.cdd['caps']['color']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsDuplex(self):
    """Verify duplex is in printer capabilities."""
    test_id = '7bda6263-a629-4e1a-84e9-28e84fa2b014'
    test_name = 'testCapsDuplex'
    try:
      self.assertIn('duplex', device.cdd['caps'])
    except AssertionError:
      notes = 'duplex not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'duplex: %s' % device.cdd['caps']['duplex']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsCopies(self):
    """Verify copies is in printer capabilities."""
    test_id = '9d1464d1-46fb-4d1c-a8fb-3fa0e7dc9509'
    test_name = 'testCapsCopies'
    if not Constants.CAPS['COPIES']:
      self.LogTest(test_id, test_name, 'Skipped', 'Copies not supported')
      return
    try:
      self.assertIn('copies', device.cdd['caps'])
    except AssertionError:
      notes = 'copies not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'copies: %s' % device.cdd['caps']['copies']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsDpi(self):
    """Verify dpi is in printer capabilities."""
    test_id = 'cd4c9dbc-da9d-4de7-a5b7-74e4618ce1b7'
    test_name = 'testCapsDpi'
    try:
      self.assertIn('dpi', device.cdd['caps'])
    except AssertionError:
      notes = 'dpi not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'dpi: %s' % device.cdd['caps']['dpi']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsMediaSize(self):
    """Verify media_size is in printer capabilities."""
    test_id = 'dae470da-ac50-47cb-8ef7-073cc856cfed'
    test_name = 'testCapsMediaSize'
    try:
      self.assertIn('media_size', device.cdd['caps'])
    except AssertionError:
      notes = 'media_size not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'media_size: %s' % device.cdd['caps']['media_size']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsCollate(self):
    """Verify collate is in printer capabilities."""
    test_id = '550f72b4-4eb0-4869-87bf-197a9ef1cf09'
    test_name = 'testCapsCollate'
    if not Constants.CAPS['COLLATE']:
      notes = 'Printer does not support collate.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    try:
      self.assertIn('collate', device.cdd['caps'])
    except AssertionError:
      notes = 'collate not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'collate: %s' % device.cdd['caps']['collate']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsPageOrientation(self):
    """Verify page_orientation is not in printer capabilities."""
    test_id = '79c696e5-33eb-4a47-a173-c698c4423b7c'
    test_name = 'testCapsPageOrientation'
    if Constants.CAPS['LAYOUT_ISSUE']:
      notes = 'Chrome issue in local printing requires orientation in caps.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
    else:
      try:
        self.assertIsNot('page_orientation', device.cdd['caps'])
      except AssertionError:
        notes = 'page_orientation found in printer capabilities.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'page_orientation not found in printer capabilities.'
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsMargins(self):
    """Verify margin is not in printer capabilities."""
    test_id = '674b3b1a-282a-4e41-a4d2-046ce65e7403'
    test_name = 'testCapsMargins'
    try:
      self.assertIsNot('margins', device.cdd['caps'])
    except AssertionError:
      notes = 'margins found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'margins not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsFitToPage(self):
    """Verify fit_to_page is not in printer capabilities."""
    test_id = '86c99c63-1581-470f-b771-94e389a5fc32'
    test_name = 'testCapsFitToPage'
    try:
      self.assertIsNot('fit_to_page', device.cdd['caps'])
    except AssertionError:
      notes = 'fit_to_page found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'fit_to_page not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsPageRange(self):
    """Verify page_range is not in printer capabilities."""
    test_id = 'f80b2077-2ed2-4fc1-a2d6-2fa3b90e9c9f'
    test_name = 'testCapsPageRange'
    try:
      self.assertIsNot('page_range', device.cdd['caps'])
    except AssertionError:
      notes = 'page_range found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'page_range not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsReverseOrder(self):
    """Verify reverse_order is not in printer capabilities."""
    test_id = 'f24797e4-090c-42fd-98e7-f19ea3d39ebf'
    test_name = 'testCapsReverseOrder'
    try:
      self.assertIsNot('reverse_order', device.cdd['caps'])
    except AssertionError:
      notes = 'reverse_order found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'reverse_order not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsHash(self):
    """Verify printer CDD contains a capsHash."""
    test_id = 'd39db864-3e18-46f3-8c16-d367f155c1e0'
    test_name = 'testCapsHash'
    try:
      self.assertIn('capsHash', device.cdd)
    except AssertionError:
      notes = 'capsHash not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'capsHash found in printer cdd.'
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsCertificationID(self):
    """Verify printer has a certificaionID and it is correct."""
    test_id = '8885e5c7-50a1-4667-aa25-4f40588e396f'
    test_name = 'testCapsCertificationID'
    try:
      self.assertIn('certificationId', device.cdd)
    except AssertionError:
      notes = 'certificationId not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertEqual(Constants.PRINTER['CERTID'],
                         device.cdd['certificationId'])
      except AssertionError:
        notes = 'Certification ID: %s, expected %s' % (
            device.cdd['certificationId'], Constants.PRINTER['CERTID'])
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Certification ID: %s' % device.cdd['certificationId']
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsResolvedIssues(self):
    """Verify printer contains resolvedIssues in printer capabilities."""
    test_id = '5a1ef1e7-26ba-458b-a72f-a5ebf26e437c'
    test_name = 'testCapsResolvedIssues'
    try:
      self.assertIn('resolvedIssues', device.cdd)
    except AssertionError:
      notes = 'resolvedIssues not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'resolvedIssues found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Passed', notes)


class PreRegistration(LogoCert):
  """Tests to be run before device is registered."""

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass()
    data_dir = 'NotSignedIn'
    cls.cd3 = _chromedriver.ChromeDriver(data_dir, cls.loadtime)
    cls.chrome3 = _chrome.Chrome(cls.cd3)

  @classmethod
  def tearDownClass(cls):
    LogoCert.tearDownClass()
    cls.cd3.CloseChrome()

  def testDeviceAdvertisePrivet(self):
    """Verify printer under test advertises itself using Privet."""
    test_id = '3382acca-15f7-46d1-9b43-2d36defa9443'
    test_name = 'testDeviceAdvertisePrivet'
    position = chrome.FindDevice('printers', self.printer)
    try:
      self.assertGreater(position, 0)
    except AssertionError:
      notes = 'device not found in new devices in chrome://devices'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Found printer in chrome, new devices.'
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testDeviceSleepingAdvertisePrivet(self):
    """Verify sleeping printer advertises itself using Privet."""
    test_id = 'fffb765b-bb62-4927-82d4-209928ef7d23'
    test_name = 'testDeviceSleepingAdvertisePrivet'
    print 'Put the printer in sleep mode.'
    raw_input('Select enter when printer is sleeping.')
    print 'Waiting 1 minute...'
    time.sleep(60)
    position = chrome.FindDevice('printers', self.printer)
    try:
      self.assertGreater(position, 0)
    except AssertionError:
      notes = 'device not found in new devices in chrome://devices'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Found printer in chrome://devices'
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testDeviceOffNoAdvertisePrivet(self):
    """Verify powered off device does not advertise using Privet."""
    test_id = '35ce7a3d-3403-499e-9a60-4d17e1693178'
    test_name = 'testDeviceOffNoAdvertisePrivet'
    print 'Power off the test device.'
    raw_input('Select enter once device is off.')
    print 'Waiting 1 minute for device state updates.'
    time.sleep(60)
    position = chrome.FindDevice('printers', self.printer)
    try:
      self.assertEqual(position, 0)
    except AssertionError:
      notes = 'device found in new device list in chrome://devices'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Powered off device not found in chrome://devices'
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testDeviceOffPowerOnAdvertisePrivet(self):
    """Verify powered on device advertises itself using Privet."""
    test_id = 'ad3c730b-dcc9-4597-8953-d9bc5dca4205'
    test_name = 'testDeviceOffPowerOnAdvertisePrivet'
    print 'Start with device powered off.'
    print 'Turn on device and wait for device to fully initialize.'
    raw_input('Select enter once device is initialized.')
    print 'Waiting 1 minute for device state updates.'
    time.sleep(60)
    position = chrome.FindDevice('printers', self.printer)
    try:
      self.assertGreater(position, 0)
    except AssertionError:
      notes = 'Device not found in chrome://devices'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Device found in chrome://devices'
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testDeviceRegistrationNotLoggedIn(self):
    """Test printer cannot be registered if user not logged in."""
    test_id = '984be779-3ca4-4bb7-a2e1-e1868f687905'
    test_name = 'testDeviceRegistrationNotLoggedIn'
    result = self.chrome3.RegisterPrinter(self.printer)
    try:
      self.assertFalse(result)
    except AssertionError:
      notes = 'Able to register printer with user signed out.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Not able to register printer with signed out Chrome.'
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testDeviceCancelRegistration(self):
    """Test printer cancellation prevents registration."""
    test_id = 'ce1c9c46-3164-4f07-aa41-241867a4a28b'
    test_name = 'testDeviceCancelRegistration'
    logger.info('Testing printer registration cancellation.')
    print 'Testing printer registration cancellation.'
    print 'Do not accept printer registration request on printer panel.'
    if chrome.RegisterPrinter(self.printer):
      raw_input('Select enter when printer registration has been cancelled')
      result = chrome.ConfirmPrinterRegistration(self.printer)
      try:
        self.assertFalse(result)
      except AssertionError:
        notes = 'Unable to cancel registration request.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Cancelled registration attempt from printer panel.'
        self.LogTest(test_id, test_name, 'Passed', notes)
    else:
      notes = 'Error attempting registration process.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

  def testLocalPrintGuestUserUnregisteredPrinter(self):
    """Verify local print for unregistered printer is correct."""
    test_id = '6e75edff-2512-4c7b-b5f0-79d2ef17d922'
    test_name = 'testLocalPrintGuestUserUnregisteredPrinter'
    data_dir = 'guest_user'
    cd3 = _chromedriver.ChromeDriver(data_dir, self.loadtime)
    chrome3 = _chrome.Chrome(cd3)
    found = chrome3.SelectPrinterFromPrintDialog(self.printer, localprint=True)
    if found:
      notes = 'Printer found in Local Destinations'
    else:
      notes = 'Printer not found in Local Destinations.'
    try:
      if Constants.CAPS['LOCAL_PRINT']:
        self.assertTrue(found)
      else:
        self.assertFalse(found)
    except AssertionError:
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.LogTest(test_id, test_name, 'Passed', notes)
    finally:
      cd3.CloseChrome()


class Registration(LogoCert):
  """Test device registration."""

  def testDeviceRegistration(self):
    """Verify printer registration using Privet and Chrome.

    This test function actually executes three tests, as it first will test that
    a device can still be registered if a user does not select accept/cancel
    for a registration attempt.
    """
    test_id = 'b36f4085-f14f-49e0-adc0-cdbaae45bd9f'
    test_name = 'testDeviceRegistration'
    test_id2 = '64f31b27-0779-4c94-8f8a-ec9d44ce6171'
    test_name2 = 'testDeviceRegistrationNoAccept'
    print 'Do not select accept/cancel registration from the printer U/I.'
    print 'Wait for the registration request to time out.'
    if chrome.RegisterPrinter(self.printer):
      raw_input('Select enter once the printer registration times out.')
      result = chrome.ConfirmPrinterRegistration(self.printer)
      try:
        self.assertFalse(result)
      except AssertionError:
        notes = 'Not able to cancel printer registration from printer UI.'
        self.LogTest(test_id2, test_name2, 'Failed', notes)
        raise
      else:
        notes = 'Cancelled printer registration from printer UI.'
        self.LogTest(test_id2, test_name2, 'Passed', notes)
    print 'Now accept the registration request from %s.' % self.username
    if chrome.RegisterPrinter(self.printer):
      self.User2RegistrationAttempt()
      #  Allow time for registration to complete.
      time.sleep(20)
      result = chrome.ConfirmPrinterRegistration(self.printer)
      try:
        self.assertTrue(result)
      except AssertionError:
        notes = 'Not able to register printer using chrome://devices.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Registered printer using chrome://devices.'
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testDeviceAcceptRegistration(self):
    """Verify printer must accept registration requests on printer panel."""
    test_id = '6968e44b-3c2d-4b14-8fd5-06c94f1e8c41'
    test_name = 'testDeviceAcceptRegistration'
    print 'Validate if printer required user to accept registration request'
    print 'If printer does not have accept/cancel on printer panel,'
    print 'Fail this test.'
    self.ManualPass(test_id, test_name, print_test=False)

  def User2RegistrationAttempt(self):
    """Verify multiple registration attempts are not allowed by device."""
    test_id = '923ee7f2-c337-49d4-aa4d-8f8e3b43621a'
    test_name = 'testMultipleRegistrationAttempt'
    data_dir = Constants.USER2['EMAIL'].split('@')[0]
    cd2 = _chromedriver.ChromeDriver(data_dir, self.loadtime)
    chrome2 = _chrome.Chrome(cd2)
    chrome2.SignIn(Constants.USER2['EMAIL'], Constants.USER2['PW'])
    if chrome2.RegisterPrinter(self.printer):
      registered = chrome2.ConfirmPrinterRegistration(self.printer)
      try:
        self.assertFalse(registered)
      except AssertionError:
        notes = 'A simultaneous registration request registered a printer!'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Simultaneous registration request was not successful.'
        self.LogTest(test_id, test_name, 'Passed', notes)
      finally:
        cd2.CloseChrome()
    else:
      notes = 'Error attempting to register printer by %s' % (
          Constants.USER2['EMAIL'])
      self.LogTest(test_id, test_name, 'Blocked', notes)


class LocalDiscovery(LogoCert):
  """Tests Local Discovery functionality."""

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass()
    LogoCert.GetDeviceDetails()
    cls.browser = _mdns.MDnsListener()
    cls.browser.add_listener('privet')

  @classmethod
  def tearDownClass(cls):
    LogoCert.tearDownClass()
    cls.browser.remove_listeners()

  def testLocalDiscoveryToggle(self):
    """Verify printer respects GCP Mgt page when local discovery toggled."""
    test_id = '54131136-9e03-4b17-acd2-7ca72e2ad732'
    test_name = 'testLocalDiscoveryToggle'
    notes = None
    notes2 = None
    printer_found = False
    failed = False

    if not gcpmgr.ToggleAdvancedOption(self.printer, 'local_discovery',
                                       toggle=False):
      notes = 'Error toggling Local Discovery.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      return
    # Give printer time to update.
    print 'Waiting 60 seconds for printer to accept changes.'
    time.sleep(60)
    for k in self.browser.listener.discovered:
      if self.printer in k:
        printer_found = True
        try:
          self.assertFalse(self.browser.listener.discovered[k])
        except AssertionError:
          notes = 'Local Discovery not disabled.'
          failed = True
          raise
        else:
          notes = 'Local Discovery successfully disabled.'
        break
    if not printer_found:
      notes = 'No printer announcement seen.'
      failed = True
    if not gcpmgr.ToggleAdvancedOption(self.printer, 'local_discovery'):
      # Local Printing is automatically turned off when Local Discovery is.
      notes = 'Error toggling Local Discovery.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      return

    gcpmgr.ToggleAdvancedOption(self.printer, 'local_printing')
    print 'Waiting 60 seconds for printer to accept changes.'
    time.sleep(60)
    for k in self.browser.listener.discovered:
      if self.printer in k:
        printer_found = True
        try:
          self.assertTrue(self.browser.listener.discovered[k])
        except AssertionError:
          notes2 = 'Local Discovery not enabled.'
          failed = True
          raise
        else:
          notes2 = 'Local Discovery successfully enabled.'
        break
    if not printer_found:
      notes2 = 'No printer announcement seen.'
      failed = True

    notes = notes + '\n' + notes2
    if failed:
      self.LogTest(test_id, test_name, 'Failed', notes)
    else:
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterOnAdvertiseLocally(self):
    """Verify printer advertises self using Privet when turned on."""
    test_id = 'e979119e-5a35-4065-89cf-1c4ef795c5b9'
    test_name = 'testPrinterOnAdvertiseLocally'
    printer_found = False
    failed = False
    print 'This test should begin with the printer turned off.'
    raw_input('Select enter once printer is powered off.')
    print 'Turn printer on.'
    raw_input('Select enter once printer is powered on and fully operationl.')
    print 'Waiting 10 seconds for printer to broadcast using mDNS.'
    time.sleep(10)  # Give printer time to send privet broadcast.

    for k in self.browser.listener.discovered:
      if self.printer in k:
        printer_found = True
        try:
          self.assertTrue(self.browser.listener.discovered[k])
        except AssertionError:
          notes = 'Printer did not broadcast privet packet.'
          failed = True
          raise
        else:
          notes = 'Printer broadcast privet packet.'
    if not printer_found:
      notes = 'Printer did not make privet packet.'
      failed = True

    if failed:
      self.LogTest(test_id, test_name, 'Failed', notes)
    else:
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterOffSendGoodbyePacket(self):
    """Verify printer sends goodbye packet when turning off."""
    test_id = '074cf049-a13c-4a7e-91ed-a0ce9457b4f4'
    test_name = 'testPrinterOffSendGoodbyePacket'
    failed = False
    printer_found = False
    print 'This test must start with the printer on and operational.'
    raw_input('Power off printer, Select enter when printer completely off.')
    time.sleep(10)
    for k in self.browser.listener.discovered:
      if self.printer in k:
        printer_found = True
        try:
          self.assertFalse(self.browser.listener.discovered[k])
        except AssertionError:
          notes = 'Printer did not send goodbye packet when powered off.'
          failed = True
          raise
        else:
          notes = 'Printer sent goodbye packet when powered off.'
    if not printer_found:
      notes = 'Printer did not send goodbye packet when powered off.'
      failed = True

    if failed:
      self.LogTest(test_id, test_name, 'Failed', notes)
    else:
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterIdleNoBroadcastPrivet(self):
    """Verify idle printer doesn't send mDNS broadcasts."""
    test_id = '703a55d2-7291-4637-b257-dc885fdb5abd'
    test_name = 'testPrinterIdleNoBroadcastPrivet'
    printer_found = False
    print 'Ensure printer stays is on and remains in idle state.'
    # Remove any broadcast entries from dictionary.
    for k in self.browser.listener.discovered.keys():
      if self.printer in k:
        del self.browser.listener.discovered[k]
    # Monitor the local network for privet broadcasts.
    print 'Listening for network broadcasts for 5 minutes.'
    time.sleep(300)
    for k in self.browser.listener.discovered:
      if self.printer in k:
        printer_found = True

    try:
      self.assertFalse(printer_found)
    except AssertionError:
      notes = 'Found printer mDNS broadcast packets containing privet.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'No printer mDNS broadcast packets containing privet were found.'
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testUpdateLocalSettings(self):
    """Verify printer's local settings can be updated with Update API."""
    test_id = '9a2fde45-ea02-4cdd-90ab-af752cbdd394'
    test_name = 'testUpdateLocalSettings'
    # Get the current xmpp timeout value.
    orig = device.cdd['local_settings']['current']['xmpp_timeout_value']
    new = orig + 600
    local_settings = '{ "pending": { "xmpp_timeout_value": %d } }' % new
    if not gcpmgr.UpdatePrinterWithUpdateAPI(device.details['Printer ID'],
                                             'local_settings', local_settings):
      notes = 'Error sending Update of local settings.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      return

    #  Give the printer time to accept and confirm the pending settings.
    time.sleep(30)
    # Refresh the values of the device.
    device.GetDeviceCDD(device.details['Printer ID'])
    timeout = device.cdd['local_settings']['current']['xmpp_timeout_value']
    try:
      self.assertEqual(timeout, new)
    except AssertionError:
      notes = 'Error setting xmpp_timeout_value in local settings.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Successfully set new xmpp_timeout_value in local settings.'
      self.LogTest(test_id, test_name, 'Passed', notes)
    finally:
      local_settings = '{ "pending": { "xmpp_timeout_value": %d } }' % orig
      gcpmgr.UpdatePrinterWithUpdateAPI(device.details['Printer ID'],
                                        'local_settings', local_settings)


class LocalPrinting(LogoCert):
  """Tests of local printing functionality.

  Note: when navigating to GMail threads sometimes ChromeDriver will hang, so
  the workaround is to first navigate to about:blank.
  """

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass()
    LogoCert.GetDeviceDetails()

  def testLocalPrintEnabled(self):
    """Verify local print is available from Chrome Print Dialog."""
    test_id = 'a47b904c-d7a2-4112-832b-59035d117404'
    test_name = 'testLocalPrintingEnabled'
    chrome.Print()
    found = chrome.SelectPrinterFromPrintDialog(self.printer, localprint=True)
    try:
      self.assertTrue(found)
    except AssertionError:
      notes = 'Not able to find printer in Local Destinations.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Found printer in local destinations.'
      self.LogTest(test_id, test_name, 'Passed', notes)
    finally:
      chrome.ClosePrintDialog()

  def testLocalPrintNotOwner(self):
    """Verify local print available to non owner of printer."""
    test_id = 'ea9b1e01-f792-4627-bf84-2db5db513da4'
    test_name = 'testLocalPrintNotOwner'
    data_dir = Constants.USER2['EMAIL'].split('@')[0]
    cd2 = _chromedriver.ChromeDriver(data_dir, self.loadtime)
    chrome2 = _chrome.Chrome(cd2)
    chrome2.SignIn(Constants.USER2['EMAIL'], Constants.USER2['PW'])
    chrome2.Print()
    found = chrome2.SelectPrinterFromPrintDialog(self.printer, localprint=True)
    try:
      self.assertTrue(found)
    except AssertionError:
      notes = 'Not able to find printer in Local Destinations.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Found printer in local destinations.'
      self.LogTest(test_id, test_name, 'Passed', notes)
    finally:
      cd2.CloseChrome()

  def testLocalPrintGuestUser(self):
    """Verify local print available to guest user."""
    test_id = '8ba6f1ba-66cc-4d9e-aa3c-1d2e611ddb38'
    test_name = 'testLocalPrintGuestUser'
    data_dir = 'guest_user'
    cd3 = _chromedriver.ChromeDriver(data_dir, self.loadtime)
    chrome3 = _chrome.Chrome(cd3)
    chrome3.Print()
    found = chrome3.SelectPrinterFromPrintDialog(self.printer, localprint=True)
    try:
      self.assertTrue(found)
    except AssertionError:
      notes = 'Not able to find printer in Local Destinations.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Found printer in Local Destinations.'
      self.LogTest(test_id, test_name, 'Passed', notes)
    finally:
      cd3.CloseChrome()

  def testLocalPrintingToggle(self):
    """Verify printer respects GCP Mgt page when local printing toggled."""
    test_id = '533d4ac6-5c1d-4c99-a91e-2bac7c31864f'
    test_name = 'testLocalPrintingToggle'
    failed = False
    if gcpmgr.ToggleAdvancedOption(self.printer, 'local_printing',
                                   toggle=False):
      # Give the printer time to update.
      print 'Waiting 60 seconds for printer to accept changes.'
      time.sleep(60)
      chrome.Print()
      found = chrome.SelectPrinterFromPrintDialog(self.printer, localprint=True)
      try:
        self.assertFalse(found)
      except AssertionError:
        notes = 'Found printer in Local Destinations when not enabled.'
        failed = True
        raise
      else:
        notes = 'Did not find printer in Local Destinations when not enabled.'
      finally:
        chrome.ClosePrintDialog()
    else:
      notes = 'Error toggling Local Printing.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    if gcpmgr.ToggleAdvancedOption(self.printer, 'local_printing'):
      print 'Waiting 60 seconds to allow printer to accept changes.'
      time.sleep(60)
      found = chrome.SelectPrinterFromPrintDialog(self.printer, localprint=True)
      try:
        self.assertTrue(found)
      except AssertionError:
        notes2 = 'Did not find printer in Local Destinations when enabled.'
        failed = True
        raise
      else:
        notes2 = 'Found printer in Local Destinations when enabled.'
      notes = notes + '\n' + notes2
      if failed:
        self.LogTest(test_id, test_name, 'Failed', notes)
      else:
        self.LogTest(test_id, test_name, 'Passed', notes)
    else:
      notes = 'Error togglging Local Printing.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

  def testLocalPrintHeadersFooters(self):
    """Verify printer respects headers and footers option in local print."""
    test_id = '26cd8c36-3107-426b-9e49-2f1beea076f9'
    test_name = 'testLocalPrintHeadersFooters'
    # First navigate to a web page to print.
    chromedriver.driver.get(chrome.devices)
    printed = chrome.PrintFromPrintDialog(self.printer, localprint=True)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing without headers and footers.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    printed = chrome.PrintFromPrintDialog(self.printer, headers=True,
                                          localprint=True)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing with headers and footers in local printing.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    print 'The 1st print job should not have headers and footers.'
    print 'The 2nd print job should have headers and footers.'
    print 'If headers and footers are incorrect, fail this test.'
    self.ManualPass(test_id, test_name)

  def testLocalPrintTwoSided(self):
    """Verify printer respects two-sided option in local print."""
    test_id = 'e235f70d-2f81-4ea4-9d0d-b56db2174a57'
    test_name = 'testLocalPrintTwoSided'
    if not Constants.CAPS['DUPLEX']:
      self.LogTest(test_id, test_name, 'Skipped', 'No Duplex support')
      return
    # First navigate to a web page to print.
    chromedriver.driver.get(Constants.GCP['LEARN'])
    printed = chrome.PrintFromPrintDialog(self.printer, duplex=True,
                                          localprint=True)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing with duplex in local printing.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    print 'Verify print job is printed in duplex.'
    self.ManualPass(test_id, test_name)

  def testLocalPrintBackground(self):
    """Verify printer respects background-graphics in local print."""
    test_id = '4ff48cf9-7329-4757-9f30-d5c30586c225'
    test_name = 'testLocalPrintBackground'
    # First navigate to a web page to print.
    chromedriver.driver.get(Constants.GOOGLE)
    printed = chrome.PrintFromPrintDialog(self.printer, localprint=True)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing locally.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    printed = chrome.PrintFromPrintDialog(self.printer, background=True,
                                          localprint=True)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing with background in local printing.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    print 'The 1st print job should not use background images.'
    print 'The 2nd print job should print with background images.'
    print 'If the background options are not observed, fail this test.'
    self.ManualPass(test_id, test_name)

  def testLocalPrintMargins(self):
    """Verify printer respects margins selected in local print."""
    test_id = 'f0143e4e-8dc1-42c1-96da-b9abc39a0b8e'
    test_name = 'testLocalPrintMargins'
    # Navigate to a page to print.
    chromedriver.driver.get(chrome.version)
    printed = chrome.PrintFromPrintDialog(self.printer, margin='None',
                                          localprint=True)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing with no margins.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    printed = chrome.PrintFromPrintDialog(self.printer, margin='Minimum',
                                          localprint=True)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing with minimum margins.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    print 'The 1st print job should have no margins.'
    print 'The 2nd print job should have minimum margins.'
    print 'If the margins are not correct, fail this test.'
    self.ManualPass(test_id, test_name)

  def testLocalPrintLayout(self):
    """Verify printer respects layout settings in local print."""
    test_id = 'fb522a69-2454-40ab-9453-270553664fea'
    test_name = 'testLocalPrintLayout'
    chromedriver.driver.get(chrome.devices)
    printed = chrome.PrintFromPrintDialog(self.printer, layout='Portrait',
                                          localprint=True)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing with portrait layout.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    printed = chrome.PrintFromPrintDialog(self.printer, layout='Landscape',
                                          localprint=True)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing with landscape layout.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    print 'The 1st print job should be printed in portrait layout.'
    print 'The 2nd print job should be printed in landscape layout.'
    print 'If the layout is not correct, fail this test.'
    self.ManualPass(test_id, test_name)

  def testLocalPrintPageRange(self):
    """Verify printer respects page range in local print."""
    test_id = '1580f47d-4115-462d-b85e-bd4d5fd4d7e3'
    test_name = 'testLocalPrintPageRange'
    chromedriver.driver.get(chrome.flags)
    printed = chrome.PrintFromPrintDialog(self.printer, page_range='2-3',
                                          localprint=True)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing with page range.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
    else:
      print 'The print job should only print pages 2 and 3.'
      print 'If this is not the case, fail this test.'
      self.ManualPass(test_id, test_name)

  def testLocalPrintCopies(self):
    """Verify printer respects copy option in local print."""
    test_id = 'c849ce7a-07e0-488e-b266-e002bdbde4d6'
    test_name = 'testLocalPrintCopies'
    if not Constants.CAPS['COPIES']:
      notes = 'Printer does not support copies option.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return

    chromedriver.driver.get(chrome.version)
    printed = chrome.PrintFromPrintDialog(self.printer, copies=2,
                                          localprint=True)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing with copies option.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
    else:
      print 'The print job should have printed 2 copies.'
      print 'If copies is not 2, fail this test.'
      self.ManualPass(test_id, test_name)

  def testLocalPrintColorSelect(self):
    """Verify printer respects color option in local print."""
    test_id = '7e0e555f-d8ac-4ec3-b268-0420baf14684'
    test_name = 'testLocalPrintColorSelect'
    if not Constants.CAPS['COLOR']:
      notes = 'Printer does not support color printing.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return

    chromedriver.driver.get('http://www.google.com/cloudprint/learn/')
    printed = chrome.PrintFromPrintDialog(self.printer, color=True,
                                          localprint=True)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing with color selected.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
    else:
      print 'Print job should be printed in color.'
      print 'If not, fail this test.'
      self.ManualPass(test_id, test_name)

  def testLocalPrintUpdateMgtPage(self):
    """Verify printer updates GCP MGT page when Local Printing."""
    test_id = '530c74f7-2764-405e-916b-21fc943ea1f8'
    test_name = 'testLocalPrintUpdateMgtPage'
    filepath = 'file://' + Constants.IMAGES['GIF4']

    chromedriver.driver.get(filepath)
    printed = chrome.PrintFromPrintDialog(self.printer, localprint=True)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing %s' % filepath
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      # Give the printer time to complete the job and update the status.
      print 'Waiting 60 seconds for job to print and status to be updated.'
      time.sleep(60)
      job_state = gcpmgr.GetJobStatus('Google-Glass.gif')
      try:
        self.assertIsNotNone(job_state)
      except AssertionError:
        notes = 'Printjob was not found on Mgt Page.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Printjob was found on Mgt Page.'
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testLocalPrintLongUrl(self):
    """Verify printer can local print a long URL."""
    test_id = '8b89286b-a5aa-4936-a7d8-e768962930d8'
    test_name = 'testLocalPrintLongUrl'
    url = ('http://www-10.lotus.com/ldd/portalwiki.nsf/dx/'
           'Determining_the_best_IBM_Lotus_Web_Content_Management_delivery'
           '_option_for_your_needs')

    chromedriver.driver.get(url)
    printed = chrome.PrintFromPrintDialog(self.printer, localprint=True)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing long url.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Verify long URL printed correctly.'
      self.ManualPass(test_id, test_name)

  def testLocalPrintHTML(self):
    """Verify printer can local print HTML file."""
    test_id = '8745d54b-045a-4378-a024-d331785ac62e'
    test_name = 'testLocalPrintHTML'
    filepath = 'file://' + Constants.IMAGES['HTML1']

    chromedriver.driver.get(filepath)
    printed = chrome.PrintFromPrintDialog(self.printer, localprint=True)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing %s' % filepath
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'HTML file should be printed.'
      print 'Fail this test is print out has errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def testLocalPrintJPG(self):
    """Verify a 1 page JPG file prints using Local Printing."""
    test_id = '01a0aa7e-80e3-4336-8183-0c5cbf8e9f19'
    test_name = 'testLocalPrintJPG'
    filepath = 'file://' + Constants.IMAGES['JPG12']

    chromedriver.driver.get(filepath)
    printed = chrome.PrintFromPrintDialog(self.printer, localprint=True)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing %s' % filepath
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'JPG file should be printed.'
      print 'Fail this test is print out has errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def testLocalPrintPNG(self):
    """Verify a 1 page PNG file prints using Local Printing."""
    test_id = 'a4588515-2c18-4f57-80c6-9c23cb57f074'
    test_name = 'testLocalPrintPNG'
    filepath = 'file://' + Constants.IMAGES['PNG6']

    chromedriver.driver.get(filepath)
    printed = chrome.PrintFromPrintDialog(self.printer, localprint=True)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing %s' % filepath
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'PNG file should be printed.'
      print 'Fail this test is print out has errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def testLocalPrintGIF(self):
    """Verify a 1 page GIF file prints using Local Printing."""
    test_id = '7b61815b-5719-4114-bdf7-8fce6e0d8dc5'
    test_name = 'testLocalPrintGIF'
    filepath = 'file://' + Constants.IMAGES['GIF4']

    chromedriver.driver.get(filepath)
    printed = chrome.PrintFromPrintDialog(self.printer, localprint=True)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing %s' % filepath
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'GIF file should be printed.'
      print 'Fail this test is print out has errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def testLocalPrintPDF(self):
    """Verify a 1 page PDF file prints using Local Printing."""
    test_id = '0a02c47a-32b0-47b4-af7a-810c002d282d'
    test_name = 'testLocalPrintPDF'
    filepath = 'file://' + Constants.IMAGES['PDF9']

    chromedriver.driver.get(filepath)
    printed = chrome.PrintFromPrintDialog(self.printer, localprint=True)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing %s' % filepath
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'PDF file should be printed.'
      print 'Fail this test if print out has errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def testLocalPrintGmail(self):
    """Verify 1 Page Gmail prints using Local Printing."""
    test_id = '20828e70-a724-4446-8932-84b7cf3adaf9'
    test_name = 'testLocalPrintGmail'

    chromedriver.driver.get('about:blank')
    chromedriver.driver.get(Constants.GOOGLE_DOCS['GMAIL1'])
    printed = chrome.PrintGoogleItem(self.printer, localprint=True)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing of 1 page gmail message.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Gmail message should be printed correctly.'
      print 'Fail this test if print out has errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def testLocalPrintGmailI18n(self):
    """Verify Gmail with attachement prints using foreign characters."""
    test_id = '5fa31002-b726-4a6a-b0d5-e21e3cc2ccf5'
    test_name = 'testLocalPrintGmailI18n'

    chromedriver.driver.get('about:blank')
    chromedriver.driver.get(Constants.GOOGLE_DOCS['GMAIL2'])
    printed = chrome.PrintGoogleItem(self.printer, localprint=True)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing Gmail with foreign characters.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Gmail message with foreign characters should print correctly.'
      print 'Fail this test if print out has errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def testLocalPrintGmailWithAttachment(self):
    """Verify Gmail with image attachment prints using Local Print."""
    test_id = '4a01ed35-2758-4ed3-ab5e-8af5dc658999'
    test_name = 'testLocalPrintGmailWithAttachment'

    chromedriver.driver.get('about:blank')
    chromedriver.driver.get(Constants.GOOGLE_DOCS['GMAIL3'])
    printed = chrome.PrintGoogleItem(self.printer, localprint=True)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing Gmail with image attachment.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Gmail message with image attachment should print correctly.'
      print 'Fail this test if print out has errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def testLocalPrintGoogleDoc(self):
    """Verify Google Doc prints using Local Print."""
    test_id = '07e05f71-9d4d-4760-93dd-471a87445261'
    test_name = 'testLocalPrintGoogleDoc'

    chromedriver.driver.get('about:blank')
    chromedriver.driver.get(Constants.GOOGLE_DOCS['DOC1'])
    printed = chrome.PrintGoogleItem(self.printer, localprint=True)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing Google Document.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Google Doc should print correctly.'
      print 'Fail this test if print out has errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def testLocalPrintGoogleSheet(self):
    """Verify Google Spreadsheet prints using Local Print."""
    test_id = '5cc856dc-4257-4d1e-89f3-71722a1a75a3'
    test_name = 'testLocalPrintGoogleDoc'

    chromedriver.driver.get('about:blank')
    chromedriver.driver.get(Constants.GOOGLE_DOCS['SHEET1'])
    printed = chrome.PrintGoogleItem(self.printer, localprint=True)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing Google Spreadsheet.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Google Spreadsheet should print correctly.'
      print 'Fail this test if print out has errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def testLocalPrintGoogleSlide(self):
    """Verify Google Presentation prints using Local Print."""
    test_id = 'e2603a90-e749-42ed-b8c3-971e7079a5bf'
    test_name = 'testLocalPrintGoogleSlide'

    chromedriver.driver.get('about:blank')
    chromedriver.driver.get(Constants.GOOGLE_DOCS['PREZ1'])
    printed = chrome.PrintGoogleItem(self.printer, localprint=True)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error local printing Google Presentation.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Google doc should print correctly.'
      print 'Fail this test if print out has errors or quality issues.'
      self.ManualPass(test_id, test_name)


class ChromePrinting(LogoCert):
  """Test with the Chrome Print Dialog.

  Note: there is an issue when directly navigating to Gmail threads that hangs
  ChromeDriver. The workaround is to first navigate to about:blank.
  """

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass()
    LogoCert.GetDeviceDetails()

  def testChromePrintPageRange(self):
    """Verify printer respects page range when printing from Chrome."""
    test_id = '553fbcb6-0d98-45a4-a0d7-308297852135'
    test_name = 'testChromePrintPageRange'
    chromedriver.driver.get(chrome.flags)
    printed = chrome.PrintFromPrintDialog(self.printer, page_range='2-3')
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing from Chrome with page range.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
    else:
      print 'The print job should only print pages 2 and 3.'
      print 'If this is not the case, fail this test.'
      self.ManualPass(test_id, test_name)

  def testChromePrintColorSelect(self):
    """Verify printer respects color option when printing from Chrome."""
    test_id = '3be1b5e6-cc96-417c-a131-ef96b0576c21'
    test_name = 'testChromePrintColorSelect'
    if not Constants.CAPS['COLOR']:
      notes = 'Printer does not support color printing.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return

    chromedriver.driver.get('http://www.google.com/cloudprint/learn/')
    printed = chrome.PrintFromPrintDialog(self.printer, color=True)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error while printing from Chrome with color selected.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
    else:
      print 'Print job should be printed in color.'
      print 'If not, fail this test.'
      self.ManualPass(test_id, test_name)

  def testChromePrintHeadersFooters(self):
    """Verify printer respects headers and footers in Chrome Print Dialog."""
    test_id = '05b8d603-4d60-4259-af11-8681ebc71ede'
    test_name = 'testChromePrintHeadersFooters'
    # First navigate to a web page to print.
    chromedriver.driver.get(chrome.devices)
    printed = chrome.PrintFromPrintDialog(self.printer)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing without headers/footers in Chrome Print Dialog.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    printed = chrome.PrintFromPrintDialog(self.printer, headers=True)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing with headers/footers in Chrome Print Dialog.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    print 'The 1st print job should not have headers and footers.'
    print 'The 2nd print job should have headers and footers.'
    print 'If headers and footers are incorrect, fail this test.'
    self.ManualPass(test_id, test_name)

  def testChromePrintTwoSided(self):
    """Verify printer respects two-sided option in Chrome Print Dialog."""
    test_id = '32c0eb04-247f-4b12-a663-66bb2a2c7920'
    test_name = 'testChromePrintTwoSided'
    if not Constants.CAPS['DUPLEX']:
      self.LogTest(test_id, test_name, 'Skipped', 'No Duplex support.')
      return
    # First navigate to a web page to print.
    chromedriver.driver.get(Constants.GCP['LEARN'])
    printed = chrome.PrintFromPrintDialog(self.printer, duplex=True)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing with duplex in Chrome Print Dialog.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    print 'Verify the print job is printed in duplex.'
    self.ManualPass(test_id, test_name)

  def testChromePrintBackground(self):
    """Verify printer respects background option in Chrome Print Dialog."""
    test_id = 'd8ea8089-3d6c-44ea-89d9-3d048a5f68f2'
    test_name = 'testChromePrintBackground'
    # First navigate to a web page to print.
    chromedriver.driver.get(Constants.GOOGLE)
    printed = chrome.PrintFromPrintDialog(self.printer)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing in Chrome Print Dialog.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    printed = chrome.PrintFromPrintDialog(self.printer, background=True)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing with background in Chrome Print Dialog.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    print 'The 1st print job should not use background images.'
    print 'The 2nd print job should print with background images.'
    print 'If the background options are not observed, fail this test.'
    self.ManualPass(test_id, test_name)

  def testChromePrintMargins(self):
    """Verify printer respects margins selected in Chrome Print Dialog."""
    test_id = 'e2178d3a-4664-4d69-a7aa-f7ac50d296a0'
    test_name = 'testChromePrintMargins'
    # Navigate to a page to print.
    chromedriver.driver.get(chrome.version)
    printed = chrome.PrintFromPrintDialog(self.printer, margin='None')
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing with no margins using Chrome Print Dialog.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    printed = chrome.PrintFromPrintDialog(self.printer, margin='Minimum')
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error with minimum margins using Chrome Print Dialog.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    print 'The 1st print job should have no margins.'
    print 'The 2nd print job should have minimum margins.'
    print 'If the margins are not correct, fail this test.'
    self.ManualPass(test_id, test_name)

  def testChromePrintLayout(self):
    """Verify printer respects layout settings using Chrome Print Dialog."""
    test_id = '96267e29-1718-4b15-9436-d94f91568048'
    test_name = 'testChromePrintLayout'
    chromedriver.driver.get(chrome.devices)
    printed = chrome.PrintFromPrintDialog(self.printer, layout='Portrait')
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing with portrait layout using Chrome Print Dialog.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    printed = chrome.PrintFromPrintDialog(self.printer, layout='Landscape')
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing with landscape layout using Chrome Print Dialog.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    print 'The 1st print job should be printed in portrait layout.'
    print 'The 2nd print job should be printed in landscape layout.'
    print 'If the layout is not correct, fail this test.'
    self.ManualPass(test_id, test_name)

  def testChromePrintCopies(self):
    """Verify printer respects copy option using Chrome Print Dialog."""
    test_id = '345affa2-796a-43e2-bc0e-2978d847d7b4'
    test_name = 'testChromePrintCopies'
    if not Constants.CAPS['COPIES']:
      notes = 'Printer does not support copies option.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return

    chromedriver.driver.get(chrome.version)
    printed = chrome.PrintFromPrintDialog(self.printer, copies=2)
    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing with copies option using Chrome Print Dialog.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
    else:
      print 'The print job should have printed 2 copies.'
      print 'If copies is not 2, fail this test.'
      self.ManualPass(test_id, test_name)

  def testChromePrintGoogleDoc(self):
    """Verify a Google Doc prints from Chrome Print Dialog."""
    test_id = '598dca3d-70e4-483e-bfc2-d62a89715a11'
    test_name = 'testChromePrintGoogleDoc'

    chromedriver.driver.get('about:blank')
    chromedriver.driver.get(Constants.GOOGLE_DOCS['DOC1'])
    printed = chrome.PrintGoogleItem(self.printer)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing Google Doc from Chrome.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Standard Google Doc should print without errors.'
      print 'Fail this test if there are errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def testChromePrintGoogleSheet(self):
    """Verify a Google Spreadsheet prints from Chrome Print Dialog."""
    test_id = 'caf2c6a3-9486-4ffe-b6f1-fa1ed8147a48'
    test_name = 'testChromePrintGoogleSheet'

    chromedriver.driver.get('about:blank')
    chromedriver.driver.get(Constants.GOOGLE_DOCS['SHEET1'])
    printed = chrome.PrintGoogleItem(self.printer)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing Google Spreadsheet from Chrome.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Google Spreadsheet should print without errors.'
      print 'Fail this test if there are errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def testChromePrintGoogleSlide(self):
    """Verify a Google Presentation prints from Chrome Print Dialog."""
    test_id = '74fb87af-e399-4fce-8bbf-af65a4b48af2'
    test_name = 'testChromePrintGoogleSlide'

    chromedriver.driver.get('about:blank')
    chromedriver.driver.get(Constants.GOOGLE_DOCS['PREZ1'])
    printed = chrome.PrintGoogleItem(self.printer)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing Google Presentation from Chrome.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Google Presentation should print without errors.'
      print 'Fail this test if there are errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def testChromePrintURL(self):
    """Verify a URL prints from Chrome Print Dialog."""
    test_id = '109b3834-e119-4518-bf76-c7f6b6896934'
    test_name = 'testChromePrintURL'

    chromedriver.driver.get('http://www.google.com')
    printed = chrome.PrintFromPrintDialog(self.printer)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing URL from Chrome.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'URL should print without errors.'
      print 'Fail this test if there are errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def testChromePrintGmail(self):
    """Verify simple 1 page Gmail prints from Chrome Print Dialog."""
    test_id = '9a957af4-eeed-47c3-8f12-7e60008a6f38'
    test_name = 'testChromePrintGmail'

    chromedriver.driver.get('about:blank')
    chromedriver.driver.get(Constants.GOOGLE_DOCS['GMAIL1'])
    printed = chrome.PrintGoogleItem(self.printer)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing simple 1 page Gmail message from Chrome.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Gmail message should print without errors.'
      print 'Fail this test if there are errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def testChromePrintGmailI18n(self):
    """Verify Gmail with foreign characters prints from Chrome Print Dialog."""
    test_id = '2af97351-0fb5-4cdc-9f71-d4666c2393d4'
    test_name = 'testChromePrintGmailI18n'

    chromedriver.driver.get('about:blank')
    chromedriver.driver.get(Constants.GOOGLE_DOCS['GMAIL2'])
    printed = chrome.PrintGoogleItem(self.printer)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing Gmail message with foreign charactersfrom Chrome.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Gmail message with foreign characters should print without errors.'
      print 'Fail this test if there are errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def testChromePrintGmailWithAttachment(self):
    """Verify Gmail with image attachment prints from Chrome Print Dialog."""
    test_id = '24f290e8-42c6-4710-8758-54b623ca51f4'
    test_name = 'testChromePrintGmailWithAttachment'

    chromedriver.driver.get('about:blank')
    chromedriver.driver.get(Constants.GOOGLE_DOCS['GMAIL3'])
    printed = chrome.PrintGoogleItem(self.printer)

    try:
      self.assertTrue(printed)
    except AssertionError:
      notes = 'Error printing Gmail message with attachment from Chrome.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Gmail message with image attachment should print without errors.'
      print 'Fail this test if there are errors or quality issues.'
      self.ManualPass(test_id, test_name)


class PostRegistration(LogoCert):
  """Tests to run after device is registered."""

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass()
    LogoCert.GetDeviceDetails()

  def testDeviceDetails(self):
    """Verify printer details are provided to Cloud Print Service."""
    test_id = '6bcf8903-af2c-439c-9c8b-1dd829521905'
    test_name = 'testDeviceDetails'
    device.GetDeviceDetails()
    try:
      self.assertIsNotNone(device.name)
    except AssertionError:
      notes = 'Error finding device in GCP MGT Page.'
      self.logger.error('Check your printer model in the _config file.')
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Found printer details on GCP MGT page.'
      device.GetDeviceCDD(device.details['Printer ID'])
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testRegisteredDeviceNoPrivetAdvertise(self):
    """Verify printer does not advertise itself once it is registered."""
    test_id = '65da1989-8273-45bc-a9f0-5826b58ab7eb'
    test_name = 'testRegisteredDeviceNoPrivetAdvertise'
    position = chrome.FindDevice('printers', self.printer)
    try:
      self.assertEqual(position, 0)
    except AssertionError:
      notes = 'Registered printer found in new devices on chrome://devices'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Printer not found in new devices on chrome://devices'
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testRegisteredDevicePoweredOffShowsOffline(self):
    """Verify device shows offline that is powered off."""
    test_id = 'ba6b2c0c-10da-4910-bb6f-63c826087054'
    test_name = 'testRegisteredDevicePoweredOffShowsOffline'
    print 'Power off device.'
    raw_input('Select enter once the printer is completely off.')
    print'Waiting up to 10 minutes for printer status update.'
    for _ in xrange(20):
      device.GetDeviceDetails()
      try:
        self.assertIn('offline', device.status)
      except AssertionError:
        time.sleep(30)
      else:
        break
    try:
      self.assertIsNotNone(device.status)
    except AssertionError:
      notes = 'Device has no status.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('offline', device.status)
    except AssertionError:
      notes = 'Device is not offline. Status: %s' % device.status
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Status: %s' % device.status
      self.LogTest(test_id, test_name, 'Passed', notes)
    finally:
      print 'Power on the devie.'
      raw_input('Select enter once the printer is completely initialized.')

  def testRegisteredDeviceNotDiscoverableAfterPowerOn(self):
    """Verify power cycled registered device does not advertise using Privet."""
    test_id = '7e4ce6cd-0ad1-4194-83f7-3ea11fa30526'
    test_name = 'testRegisteredDeviceNotDiscovereableAfterPowerOn'
    print 'Power off registered device.'
    print 'After device powers down, turn on device.'
    raw_input('Once device is fully initialized select enter.')
    print 'Waiting 1 minute for state updates.'
    time.sleep(60)
    position = chrome.FindDevice('printers', self.printer)
    try:
      self.assertEqual(position, 0)
    except AssertionError:
      notes = 'Registered device found in new devices on chrome://devices'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Registered device not found in new devices.'
      self.LogTest(test_id, test_name, 'Passed', notes)


class PrinterState(LogoCert):
  """Test that printer state is reported correctly."""

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass()
    LogoCert.GetDeviceDetails()

  def testLostNetworkConnection(self):
    """Verify printer that loses network connection reconnects properly."""
    test_id = '0af4301e-bacb-40c4-8b95-a8b29aefc8dd'
    test_name = 'testLostNetworkConnection'
    print 'Test printer handles connection status when reconnecting to network.'
    raw_input('Select enter once printer loses network connection.')
    print 'Waiting 60 seconds.'
    time.sleep(60)
    print 'Now reconnect printer to the network.'
    raw_input('Select enter once printer has network connection.')
    print 'Waiting 60 seconds.'
    time.sleep(60)
    device.GetDeviceDetails()
    try:
      self.assertIn('online', device.status)
    except AssertionError:
      notes = 'Device status is not online.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Device status is online.'
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testOpenPaperTray(self):
    """Verifuy if open paper tray is reported correctly."""
    test_id = '519969fa-97d1-4116-84e7-4f1f689e1df7'
    test_name = 'testOpenPaperTray'
    if not Constants.CAPS['TRAY_SENSOR']:
      notes = 'Printer does not have paper tray sensor.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    print 'Open the paper tray to the printer.'
    raw_input('Select enter once the paper tray is open.')
    time.sleep(10)
    device.GetDeviceDetails()
    try:
      self.assertTrue(device.error_state)
    except AssertionError:
      notes = 'Printer is not in error state with open paper tray.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Open paper tray alert should be reported on GCP Mgt page.'
      print 'If not, fail this test.'
      self.ManualPass(test_id, test_name, print_test=False)

  def testClosedPaperTray(self):
    """Verify open to closed paper tray is reported correctly."""
    test_id = '5041f9a4-0b58-451a-906f-dec2375d93a4'
    test_name = 'testClosedPaperTray'
    if not Constants.CAPS['TRAY_SENSOR']:
      notes = 'Printer does not have paper tray sensor.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    print 'Start with open paper tray.'
    print 'GCP Mgt page should report an open paper tray.'
    raw_input('Select enter when the GCP Mgt Page show open tray alert.')
    print 'Now close the paper tray.'
    raw_input('Select enter once the paper tray is closed.')
    time.sleep(10)
    device.GetDeviceDetails()
    try:
      self.assertFalse(device.error_state)
    except AssertionError:
      notes = 'Paper tray is closed but printer reports error.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Closed paper tray should not be reported by GCP Mgt page.'
      print 'If reported, fail this test.'
      self.ManualPass(test_id, test_name, print_test=False)

  def testNoMediaInTray(self):
    """Verify no media in paper tray reported correctly."""
    test_id = 'e8001a2a-e403-4f5a-94e5-59e61528d161'
    test_name = 'testNoMediaInTray'
    if not Constants.CAPS['TRAY_SENSOR']:
      notes = 'Printer does not have a paper tray sensor.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    print 'Remove all media from the paper tray.'
    raw_input('Select enter once all media is removed.')
    time.sleep(10)
    device.GetDeviceDetails()
    try:
      self.assertTrue(device.error_state)
    except AssertionError:
      notes = 'Printer not in error state with no media in paper tray.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'GCP Mgt page should show empty paper tray alert.'
      print 'Fail this test if it does not.'
      self.ManualPass(test_id, test_name, print_test=False)

  def testMediaInTray(self):
    """Verify when media put in empty tray, printer state is updated."""
    test_id = '64e592be-d6c4-424e-9e69-021c92b09953'
    test_name = 'testMediaInTray'
    if not Constants.CAPS['TRAY_SENSOR']:
      notes = 'Printer does not have a paper tray sensor.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    print 'Start with no media in paper tray.'
    raw_input('Select enter when GCP Mgt page shows missing media alert.')
    print 'Place media in empty paper tray.'
    raw_input('Select enter once you have placed paper in paper tray.')
    time.sleep(10)
    device.GetDeviceDetails()
    try:
      self.assertFalse(device.error_state)
    except AssertionError:
      notes = 'Papaer in media tray but printer in error state.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'GCP Mgt page should not show missing paper alert.'
      print 'If it has alert, fail this test.'
      self.ManualPass(test_id, test_name, print_test=False)

  def testRemoveTonerCartridge(self):
    """Verify missing toner cartridge is reported correctly."""
    test_id = '3be1a76e-b60f-4166-aeb2-0feed9de67c8'
    test_name = 'testRemoveTonerCartridge'
    if not Constants.CAPS['TONER']:
      notes = 'Printer does not contain ink toner.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return True
    print 'Remove the (or one) toner cartridge from the printer.'
    raw_input('Select enter once the toner cartridge is removed.')
    time.sleep(10)
    device.GetDeviceDetails()
    try:
      self.assertTrue(device.error_state)
    except AssertionError:
      notes = 'Printer is not in error state with missing toner cartridge.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'The GCP Mgt Page should show alert for missing toner cartridge.'
      print 'If it does not, faile this test.'
      self.ManualPass(test_id, test_name, print_test=False)

  def testExhaustTonerCartridge(self):
    """Verify empty toner is reported correctly."""
    test_id = 'b73b5b6b-9398-48ad-9646-dbb501b32f8c'
    test_name = 'testExhaustTonerCartridge'
    if not Constants.CAPS['TONER']:
      notes = 'Printer does not contain ink toner.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    print 'Insert an empty toner cartridge in printer.'
    raw_input('Select enter once an empty toner cartridge is in printer.')
    time.sleep(10)
    device.GetDeviceDetails()
    try:
      self.assertTrue(device.error_state)
    except AssertionError:
      notes = 'Printer is not in error state with empty toner.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'The GCP Mgt Page should show alert for empty toner.'
      print 'If it does not, fail this test.'
      self.ManualPass(test_id, test_name, print_test=False)

  def testReplaceMissingToner(self):
    """Verify correct printer state after replacing missing toner cartridge."""
    test_id = 'e2a57ebb-97cf-4f36-b405-0d753d4a862c'
    test_name = 'testReplaceMissingToner'
    if not Constants.CAPS['TONER']:
      notes = 'Printer does not contain ink toner.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    print 'Start test with missing toner cartridge'
    raw_input('Select enter once toner is removed from printer.')
    print 'Verify the GCP Mgt page shows missing toner alert.'
    raw_input('Select enter once toner is replaced in printer.')
    time.sleep(10)
    device.GetDeviceDetails()
    try:
      self.assertFalse(device.error_state)
    except AssertionError:
      notes = 'Printer is in error state with good toner cartridge.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'The GCP Mgt page should not show missing toner alert.'
      print 'If it does, fail this test.'
      self.ManualPass(test_id, test_name, print_test=False)

  def testCoverOpen(self):
    """Verify that an open door or cover is reported correctly."""
    test_id = 'b4d4f888-2a97-4ab4-aab8-c847046616f8'
    test_name = 'testCoverOpen'
    if not Constants.CAPS['COVER']:
      notes = 'Printer does not have a cover.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    print 'Open a cover on your printer.'
    raw_input('Select enter once the cover has been opened.')
    time.sleep(10)
    device.GetDeviceDetails()
    try:
      self.assertTrue(device.error_state)
    except AssertionError:
      notes = 'Printer error state is not True with open cover.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'The GCP Mgt Page should show alert of open door or cover'
      print 'If it does not, fail this test.'
      self.ManualPass(test_id, test_name, print_test=False)

  def testCoverClosed(self):
    """Verify that printer updates state from open to closed cover."""
    test_id = 'a26b7d34-15b4-4819-84a5-4b8e5bc3a30e'
    test_name = 'testCoverClosed'
    if not Constants.CAPS['COVER']:
      notes = 'Printer does not have a cover.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    print 'Start with open cover to printer.'
    raw_input('Select enter once you see open cover indicator on GCP MGT page')
    print 'Now close the printer cover.'
    raw_input('Select enter once the printer cover is closed.')
    time.sleep(10)
    device.GetDeviceDetails()
    try:
      self.assertFalse(device.error_state)
    except AssertionError:
      notes = 'Printer error state is True with closed cover.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'The GCP Mgt Page should remove alert about open door.'
      print 'If it does not, fail this test.'
      self.ManualPass(test_id, test_name, print_test=False)

  def testPaperJam(self):
    """Verify printer properly reports a paper jam with correct state."""
    test_id = 'fe089b80-0e1b-4f28-9239-42b8d65724ac'
    test_name = 'testPaperJam'
    print 'Cause the printer to become jammed with paper.'
    raw_input('Select enter once the printer has become jammed.')
    time.sleep(10)
    device.GetDeviceDetails()
    try:
      self.assertTrue(device.error_state)
    except AssertionError:
      notes = 'Printer is not in error state with paper jam.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'The GCP Mgt Page should show alert about papaer jam.'
      print 'If it does not, fail this test.'
      self.ManualPass(test_id, test_name, print_test=False)

  def testRemovePaperJam(self):
    """Verify removing paper jam in printer reports correct state."""
    test_id = 'ff7e0f11-4955-4510-8a5c-91f809f6b263'
    test_name = 'testRemovePaperJam'
    print 'Start with paper jam in printer.'
    raw_input('Select enter once paper jam is reported on GCP Mgt page.')
    print 'Now clear the paper jam.'
    raw_input('Select enter once the paper jam is clear from printer.')
    time.sleep(10)
    device.GetDeviceDetails()
    try:
      self.assertFalse(device.error_state)
    except AssertionError:
      notes = 'Printer is in error after paper jam was cleared.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'The GCP Mgt page should not report paper jam.'
      print 'If it does, fail this test.'
      self.ManualPass(test_id, test_name, print_test=False)


class JobState(LogoCert):
  """Test that print jobs are reported correctly from the printer."""

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass()
    LogoCert.GetDeviceDetails()

  def testOnePagePrintJob(self):
    """Verify a 1 page print job is reported correctly."""
    test_id = '345f2083-ec94-4548-9c01-ad7d8f1840ec'
    test_name = 'testOnePagePrintJobState'
    print 'Wait for this one page print job to finish.'
    output = chrome.PrintFile(self.printer, Constants.IMAGES['JPG6'])
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing one page JPG file.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      raw_input('Select enter once image has finished printing.')
      # Now give the printer time to update our service.
      time.sleep(10)
      pages_printed = gcpmgr.GetPagesPrinted('GoogleGlass.jpg')
      try:
        self.assertEqual(pages_printed, 1)
      except AssertionError:
        notes = 'Pages printed is not equal to 1.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Printed one page as expected. Status shows as printed.'
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testMultiPagePrintJob(self):
    """Verify a multi-page print job is reported with correct state."""
    test_id = '7bbf3e1f-c972-4414-ad7c-e6054aa7416f'
    test_name = 'testMultiPageJobState'
    print 'Wait until job starts printing 7 page PDF file...'
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF1.7'])
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error while printing 7 page PDF file.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      raw_input('Select enter once 1st page is printed...')
      job_state = gcpmgr.GetJobStatus('PDF1.7.pdf')
      try:
        self.assertEqual(job_state, 'In progress')
      except AssertionError:
        notes = 'Job is no "In progress" while job is still printing.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        raw_input('Select enter once all 7 pages are printed...')
        # Give the printer time to update our service.
        time.sleep(10)
        pages_printed = gcpmgr.GetPagesPrinted('PDF1.7.pdf')
        try:
          self.assertEqual(pages_printed, 7)
        except AssertionError:
          notes = 'Pages printed is not equal to 7.'
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        else:
          notes = 'Printed 7 pages, and job state correctly updated.'
          self.LogTest(test_id, test_name, 'Passed', notes)

  def testJobDeletionRecovery(self):
    """Verify printer recovers from an In-Progress job being deleted."""
    test_id = 'd270088d-0a95-416c-98ab-c703cadde1c3'
    test_name = 'testJobDeletionRecovery'
    if chrome.PrintFile(self.printer, Constants.IMAGES['PDF1.7']):
      raw_input('Select enter once the first page prints out.')
      if gcpmgr.DeleteJob('PDF1.7.pdf'):
        # Since it's PDF file give the job time to finish printing.
        time.sleep(10)
        output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG7'])
        try:
          self.assertTrue(output)
        except AssertionError:
          notes = 'Error printing job after deleting IN_PROGRESS job.'
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        else:
          print 'Printer Test Page should print after job deletion.'
          print 'Fail this test if Printer Test Page does not print.'
          self.ManualPass(test_id, test_name)
      else:
        notes = 'Error deleting IN_PROGRESS job.'
        logger.error(notes)
        self.LogTest(test_id, test_name, 'Blocked', notes)
        raise
    else:
      notes = 'Error printing multi-page PDF file.'
      logger.error(notes)
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise

  def testJobStateEmptyInputTray(self):
    """Validate proper /control msg when input tray is empty."""
    test_id = '3e178014-b2b6-4ee0-b9b5-f2df24be10b0'
    test_name = 'testJobStateEmptyInputTray'
    print 'Empty the input tray of all paper.'
    raw_input('Select enter once input tray has been emptied.')
    if chrome.PrintFile(self.printer, Constants.IMAGES['PDF1.7']):
      # give printer time to update our service.
      time.sleep(10)
      job_state = gcpmgr.GetJobStatus('PDF1.7.pdf')
      try:
        self.assertEqual(job_state, 'Error')
      except AssertionError:
        notes = 'Print Job is not in Error state.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        job_state_msg = gcpmgr.GetJobDetailsStateMsg('PDF1.7.pdf')
        notes = 'Job State Error msg: %s' % job_state_msg
        try:
          self.assertIn('tray', job_state_msg)
        except AssertionError:
          logger.error('The Job State error message did not contain tray')
          logger.error(notes)
          logger.error('Note that the error message may be ok.')
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        else:
          print 'Now place paper back in the input tray.'
          raw_input('Once paper starts printing, select enter...')
          time.sleep(10)
          job_state = gcpmgr.GetJobStatus('PDF1.7.pdf')
          try:
            self.assertEqual(job_state, 'In progress')
          except AssertionError:
            notes = 'Job is not in progress: %s' % job_state
            logger.error(notes)
            self.LogTest(test_id, test_name, 'Failed', notes)
            raise
          else:
            print 'Wait for the print job to finish.'
            raw_input('Select enter once the job completes printing...')
            time.sleep(10)
            job_state = gcpmgr.GetJobStatus('PDF1.7.pdf')
            try:
              self.assertEqual(job_state, 'Printed')
            except AssertionError:
              notes = 'Job is not in Printed state: %s' % job_state
              logger.error(notes)
              self.LogTest(test_id, test_name, 'Failed', notes)
              raise
            else:
              notes = 'Job state: %s' % job_state
              self.LogTest(test_id, test_name, 'Passed', notes)
    else:
      notes = 'Error printing PDF file.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise

  def testJobStateMissingToner(self):
    """Validate proper /control msg when toner or ink cartridge is missing."""
    test_id = '88ae0238-c866-41eb-b5c1-dea43b902335'
    test_name = 'testJobStateMissingToner'
    if not Constants.CAPS['TONER']:
      notes = 'printer does not contain toner ink.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    print 'Remove ink cartridge or toner from the printer.'
    raw_input('Select enter once the toner is removed.')
    if chrome.PrintFile(self.printer, Constants.IMAGES['PDF1.7']):
      # give printer time to update our service.
      time.sleep(10)
      job_state = gcpmgr.GetJobStatus('PDF1.7.pdf')
      try:
        self.assertEqual(job_state, 'Error')
      except AssertionError:
        notes = 'Print Job is not in Error state.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        job_state_msg = gcpmgr.GetJobDetailsStateMsg('PDF1.7.pdf')
        notes = 'Job State Error msg: %s' % job_state_msg
        try:
          # Ensure the message at least has the string or more than 4 chars.
          self.assertGreater(len(job_state_msg), 4)
        except AssertionError:
          logger.error('The Job State error message is insufficient')
          logger.error(notes)
          logger.error('Note that the error message may be ok.')
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        else:
          print 'Now place toner or ink back in printer.'
          raw_input('Once paper starts printing, select enter...')
          time.sleep(10)
          job_state = gcpmgr.GetJobStatus('PDF1.7.pdf')
          try:
            self.assertEqual(job_state, 'In progress')
          except AssertionError:
            notes = 'Job is not in progress: %s' % job_state
            logger.error(notes)
            self.LogTest(test_id, test_name, 'Failed', notes)
            raise
          else:
            print 'Wait for the print job to finish.'
            raw_input('Select enter once the job completes printing...')
            time.sleep(10)
            job_state = gcpmgr.GetJobStatus('PDF1.7.pdf')
            try:
              self.assertEqual(job_state, 'Printed')
            except AssertionError:
              notes = 'Job is not in Printed state: %s' % job_state
              logger.error(notes)
              self.LogTest(test_id, test_name, 'Failed', notes)
              raise
            else:
              notes = 'Job state: %s' % job_state
              self.LogTest(test_id, test_name, 'Passed', notes)
    else:
      notes = 'Error printing PDF file.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise

  def testJobStateNetworkOutage(self):
    """Validate proper /control msg when there is network outage."""
    test_id = '52f25929-6970-400f-93b1-e1542309f31f'
    test_name = 'testJobStateNetworkOutage'
    print 'Once the printer prints 1 page, disconnect printer from network.'
    if chrome.PrintFile(self.printer, Constants.IMAGES['PDF1.7']):
      print 'Wait for one page to print.'
      raw_input('Select enter once network is disconnected.')
      time.sleep(10)
      job_state = gcpmgr.GetJobStatus('PDF1.7.pdf')
      try:
        self.assertEqual(job_state, 'In progress')
      except AssertionError:
        notes = 'Print Job is not In progress.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        print 'Re-establish network connection to printer.'
        raw_input('Select enter once network has been restored....')
        time.sleep(10)
        job_state = gcpmgr.GetJobStatus('PDF1.7.pdf')
        try:
          self.assertEqual(job_state, 'In progress')
        except AssertionError:
          notes = 'Job is not in progress: %s' % job_state
          logger.error(notes)
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        else:
          print 'Wait for the print job to finish.'
          raw_input('Select enter once the job completes printing...')
          time.sleep(10)
          job_state = gcpmgr.GetJobStatus('PDF1.7.pdf')
          try:
            self.assertEqual(job_state, 'Printed')
          except AssertionError:
            notes = 'Job is not in Printed state: %s' % job_state
            logger.error(notes)
            self.LogTest(test_id, test_name, 'Failed', notes)
            raise
          else:
            notes = 'Job state: %s' % job_state
            self.LogTest(test_id, test_name, 'Passed', notes)
    else:
      notes = 'Error printing PDF file.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise

  def testJobStateWithPaperJam(self):
    """Validate proper behavior of print job when paper is jammed."""
    test_id = '664a8841-14d0-483e-a91a-34722dfdb298'
    test_name = 'testJobStateWithPaperJam'
    print 'This test will validate job state when there is a paper jam.'
    print 'Place page inside print path to cause a paper jam.'
    raw_input('Select enter once printer reports paper jam.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF9'])
    print 'Verify job is reported in error state.'
    print 'Now clear the print path so the printer is no longer jammed.'
    raw_input('Select enter once printer is clear of jam.')
    print 'Verify print job prints after paper jam is cleared.'
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing %s' % Constants.IMAGES['PDF9']
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testJobStateIncorrectMediaSize(self):
    """Validate proper behavior when incorrect media size is selected."""
    test_id = '0c5a757c-ab57-4383-b286-1503c09ad81f'
    test_name = 'testJobStateIncorrectMediaSize'
    print 'This test is designed to select media size that is not available.'
    print 'The printer should prompt the user to enter the requested size.'
    print 'Load input tray with letter sized paper.'
    raw_input('Select enter once paper tray loaded with letter sized paper.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG7'],
                              size='A4')
    print 'Attempting to print with A4 media size.'
    print 'Fail this test if printer does not warn user to load correct size'
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing %s' % Constants.IMAGES['PNG7']
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testMultipleJobsPrint(self):
    """Verify multiple jobs in queue are all printed."""
    test_id = '50790aa4-f276-4c12-9a06-fc0fdf446d7e'
    test_name = 'testMultipleJobsPrint'
    print 'This tests that multiple jobs in print queue are printed.'
    for _ in xrange(3):
      output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG7'])
      time.sleep(5)
      try:
        self.assertTrue(output)
      except AssertionError:
        notes = 'Error printing %s' % Constants.IMAGES['PNG7']
        self.LogTest(test_id, test_name, 'Blocked', notes)
        raise

    print 'Verify all 3 job printed correctly.'
    print 'If all 3 Print Test pages are not printed, fail this test.'
    self.ManualPass(test_id, test_name)

  def testPrintToOfflinePrinter(self):
    """Validate offline printer prints all queued jobs when back online."""
    test_id = '0f3a6cb5-bc4c-4fe9-858a-799d58082b23'
    test_name = 'testPrintToOfflinePrinter'

    print 'This tests that an offline printer will print all jobs'
    print 'when it comes back online.'
    raw_input('Turn off printer. Select enter when printer is off.')

    for _ in xrange(3):
      output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG7'])
      time.sleep(10)
      job_state = gcpmgr.GetJobStatus('testpage.png')
      try:
        self.assertTrue(output)
      except AssertionError:
        notes = 'Error printing %s' % Constants.IMAGES['PNG7']
        self.LogTest(test_id, test_name, 'Blocked', notes)
        raise
      try:
        self.assertEqual(job_state, 'Queued')
      except AssertionError:
        notes = 'Print job is not in Queued state.'
        self.LogTest(test_id, test_name, 'Blocked', notes)
        raise

    print 'Now power on printer.'
    raw_input('Select enter once printer is on and operational.')
    print 'Verify that all 3 print jobs are printed.'
    raw_input('Select enter once printer has fetched all jobs.')
    self.ManualPass(test_id, test_name)

  def testDeleteJobFromMgtPage(self):
    """Verify deleting job from Mgt Page is properly handled by printer."""
    test_id = '6a449854-a0d9-480b-82e0-f04342f6793a'
    test_name = 'testDeleteJobFromMgtPage'

    print 'Start with printer power off.'
    raw_input('Select enter when printer is powered completely off.')

    output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG7'])
    time.sleep(10)
    job_state = gcpmgr.GetJobStatus('testpage.png')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing %s' % Constants.IMAGES['PNG7']
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    try:
      self.assertEqual(job_state, 'Queued')
    except AssertionError:
      notes = 'Print job is not in queued state.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise

    print 'Attempting to delete job in queued state.'
    job_delete = gcpmgr.DeleteJob('testpage.png')
    try:
      self.assertTrue(job_delete)
    except AssertionError:
      notes = 'Queued job not deleted.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      print 'Turn printer on.'
      raw_input('Select enter once printer is fully powered on.')
      print 'Verify printer does not go into error state because of deleted job'
      self.ManualPass(test_id, test_name)

  def testMalformattedFile(self):
    """Verify print recovers from malformatted print job."""
    test_id = 'eb71a35f-3fc8-4e3b-a4c8-6cda4cf4f3b4'
    test_name = 'testMalformattedFile'
    test_id2 = '2e9d33c1-7611-4d5c-90b5-dd5282b36479'
    test_name2 = 'testErrorRecovery'

    print 'Submitting a malformatted PDF file.'

    # First printing a malformatted PDF file. Not expected to print.
    chrome.PrintFile(self.printer, Constants.IMAGES['PDF5'])
    time.sleep(10)
    # Now print a valid file.
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF9'])
    time.sleep(10)
    job_state = gcpmgr.GetJobStatus('printtest.pdf')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Job did not print after malformatted print job.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertEqual(job_state, 'Printed')
    except AssertionError:
      notes = 'Print Job is not in Printed state.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Verify malformatted file did not put printer in error state.'
      self.ManualPass(test_id, test_name)
      print 'Verify print test page printed correctly.'
      self.ManualPass(test_id2, test_name2)

  def testPagesPrinted(self):
    """Verify printer properly reports number of pages printed."""
    test_id = 'e078c865-738a-44a7-bf32-cff5c47d0857'
    test_name = 'testPagesPrinted'

    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF10'])
    raw_input('Select enter when the 3 page print job is completed.')
    pages_printed = gcpmgr.GetPagesPrinted('rosemary.pdf')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing 3 page PDF file.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      try:
        self.assertEqual(pages_printed, 3)
      except AssertionError:
        notes = 'Printer reports pages printed not equal to 3.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Printer reports pages printed = 3.'
        self.LogTest(test_id, test_name, 'Passed', notes)


class RunAfter24Hours(LogoCert):
  """Tests to be run after printer sits idle for 24 hours."""

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass()
    logger.info('Sleeping for 1 day before running additional tests.')
    print 'Sleeping for 1 day before running additional tests.'
    time.sleep(86400)

  def testPrinterOnline(self):
    """validate printer has online status."""
    test_id = '5e0bf694-086a-4258-b23a-aa0d9a746dd7'
    test_name = 'testPrinterOnline'
    device.GetDeviceDetails()
    try:
      self.AssertIn('online', device.status)
    except AssertionError:
      notes = 'Printer is not online after 24 hours.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Printer online after 24 hours.'
      self.LogTest(test_id, test_name, 'Passed', notes)


class Unregister(LogoCert):
  """Test removing device from registered status."""

  def testUnregisterDevice(self):
    """Delete printer using the Cloud Print Management page."""
    test_id = 'bd9cdf91-431a-4534-a747-55ef8cbd8391'
    test_name = 'testUnregisterDevice'
    test_id2 = 'a6054736-ee47-4db4-8ad9-640ed987ac75'
    test_name2 = 'testOffDeviceIsDeleted'
    print 'Power down registered device.'
    raw_input('Select return once device is completely powered down.')
    result = gcpmgr.DeletePrinter(self.printer)
    try:
      self.assertTrue(result)
    except AssertionError:
      notes = 'Error while deleting registered printer.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Registered printer was deleted.'
      self.LogTest(test_id, test_name, 'Passed', notes)
    print 'Power on device.'
    raw_input('Once device has completely initialized, select enter.')
    # Need to wait 5 minutes for device to start advertising itself.
    print 'Waiting 1 minute for state updates.'
    time.sleep(60)
    position = chrome.FindDevice('printers', self.printer)
    try:
      self.assertGreater(position, 0)
    except AssertionError:
      notes = 'Deleted device not found in new devices on chrome://devices'
      self.LogTest(test_id2, test_name2, 'Failed', notes)
      raise
    else:
      notes = 'Deleted device found in new devices on chrome://devices'
      self.LogTest(test_id2, test_name2, 'Passed', notes)


class PostUnregister(LogoCert):
  """Tests to be run after a device has been deleted from registration."""

  def testUnregisteredDevicePrivetAdvertise(self):
    """Verify an unregistered device advertises itself using Privet."""
    test_id = '015c45ee-ba09-47b0-ab2d-53453410de4d'
    test_name = 'testUnregisteredDevicePrivetAdvertise'
    position = chrome.FindDevice('printers', self.printer)
    try:
      self.assertGreater(position, 0)
    except AssertionError:
      notes = 'Unregistered printer not found in new devices in Chrome Devices.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Found unregistered printer in chrome, new devices.'
      self.LogTest(test_id, test_name, 'Passed', notes)


class Printing(LogoCert):
  """Test printing using Cloud Print."""

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass()
    LogoCert.GetDeviceDetails()

  def testPrintJpg2Copies(self):
    test_id = '734537e6-c075-4d38-bc4b-dd1b6ad1a7ca'
    test_name = 'testPrintJpg2Copies'
    if not Constants.CAPS['COPIES']:
      notes = 'Copies not supported.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    logger.info('Setting copies to 2...')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['JPG12'],
                              color=self.color, copies=2)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing with copies = 2.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintLandscape(self):
    test_id = '2b7c81a9-9014-4236-8a1f-5daf4824a41a'
    test_name = 'testPrintJpgLandscape'
    logger.info('Setting orientation to landscape...')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['JPG7'],
                              color=self.color, layout='Landscape')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing in landscape'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintPdfDuplexLongEdge(self):
    test_id = 'cb86137b-943d-47fc-adcd-663ad9f0dce8'
    test_name = 'testPrintPdfDuplexLongEdge'
    if not Constants.CAPS['DUPLEX']:
      notes = 'Duplex not supported.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    logger.info('Setting duplex to long edge...')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF10'],
                              duplex='Long Edge')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing in duplex long edge.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintPdfDuplexShortEdge(self):
    test_id = '651588ca-c4aa-4710-b203-64085834dd17'
    test_name = 'testPrintPdfDuplexShortEdge'
    if not Constants.CAPS['DUPLEX']:
      notes = 'Duplex not supported.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    logger.info('Setting duplex to short edge...')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF10'],
                              duplex='Short Edge')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing in duplex short edge.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintColorSelect(self):
    """Verify the management page has color options."""
    test_id = '52686084-5ae2-4bda-b715-aba6a8972268'
    test_name = 'testPrintColorSelect'
    if not Constants.CAPS['COLOR']:
      notes = 'Color is not supported.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    logger.info('Printing with color selected.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF13'],
                              color='Color')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing color PDF with color selected.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintMediaSizeSelect(self):
    test_id = '14ee1e62-7b38-423c-8637-50a2ae460ddc'
    test_name = 'testPrintMediaSizeSelect'
    logger.info('Testing the selection of A4 media size.')
    raw_input('Load printer with A4 size paper. Select return when ready.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG1'],
                              size='A4')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error selecting A4 media size.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)
    raw_input('Load printer with letter size papaer. Select return when ready.')

  def testPrintPdfReverseOrder(self):
    test_id = '1c2610c9-4f16-42ca-9d4a-018f127c4b58'
    test_name = 'testPrintPdfReverseOrder'
    logger.info('Print with reverse order flag set...')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF10'],
                              reverse=True)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing in reverse order.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintPdfPageRangePage2(self):
    test_id = '4f274ec1-28f0-4201-b769-65467f7abcfd'
    test_name = 'testPrintPdfPageRangePage2'
    logger.info('Setting page range to page 2...')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF1'],
                              pagerange='2')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing with page range set to page 2.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgDpiSetting(self):
    test_id = '93c42b61-30e9-407c-bcd5-df50f418c53b'
    test_name = 'testPrintJpgDpiSetting'
    dpi_settings = chrome.GetOptions('dpi', self.printer)
    for dpi_option in dpi_settings:
      logger.info('Setting dpi to %s', dpi_option)
      output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG8'],
                                dpi=dpi_option)
      try:
        self.assertTrue(output)
      except AssertionError:
        notes = 'Error printing with dpi set to %s' % dpi_option
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
    self.ManualPass(test_id, test_name)

  def testPrintPngFillPage(self):
    test_id = '0f911f5f-7001-4d87-933f-c15f42823da6'
    test_name = 'testPrintPngFillPage'
    logger.info('Setting print option to Fill Page...')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG3'],
                              pagefit='Fill Page')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing with Fill Page option.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintPngFitToPage(self):
    test_id = '5f2ab7d7-663b-4b86-b4e5-c38979baad11'
    test_name = 'testPrintPngFitToPage'
    logger.info('Setting print option to Fit to Page...')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG3'],
                              pagefit='Fit to Page')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing with Fit to Page option.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintPngGrowToPage(self):
    test_id = '09532b30-f853-458e-99bf-5c1c532573c8'
    test_name = 'testPrintPngGrowToPage'
    logger.info('Setting print option to Grow to Page...')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG3'],
                              pagefit='Grow to Page')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing with Grow To Page option.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintPngShrinkToPage(self):
    test_id = '3309482d-d23a-4ad7-8161-8c474ab1e6de'
    test_name = 'testPrintPngShrinkToPage'
    logger.info('Setting print option to Shrink to Page...')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG3'],
                              pagefit='Shrink to Page')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing with Shrink To Page option.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintPngNoFitting(self):
    test_id = '0c8c1bd5-7d2a-4f51-9219-36d1f6957b57'
    test_name = 'testPrintPngNoFitting'
    logger.info('Setting print option to No Fitting...')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG3'],
                              pagefit='No Fitting')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing with No Fitting option.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgPortrait(self):
    test_id = '6e36efd8-fb5b-4fce-8d24-2cc1097a88f5'
    test_name = 'testPrintJpgPortrait'
    logger.info('Print simple JPG file with portrait orientation.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['JPG14'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing JPG file in portrait orientation.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgLandscape(self):
    test_id = '1d97a167-bc37-4e24-adf9-7e4bdbfff553'
    test_name = 'testPrintJpgLandscape'
    logger.info('Print simple JPG file with landscape orientation.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['JPG7'],
                              color=self.color, layout='Landscape')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing JPG file with landscape orientation.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgBlacknWhite(self):
    test_id = 'bbd3c533-fcc2-4bf1-adc9-9cd63cc35a80'
    test_name = 'testPrintJpgBlacknWhite'
    logger.info('Print black and white JPG file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['JPG1'],
                              color='Monochrome')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing black and white JPG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgColorTestLandscape(self):
    test_id = '26076864-6aad-44e5-96a6-4f455e751fe7'
    test_name = 'testPrintJpgColorTestLandscape'
    logger.info('Print color test JPG file with landscape orientation.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['JPG2'],
                              color=self.color, layout='Landscape')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing color test JPG file with landscape orientation.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgPhoto(self):
    test_id = '1f0e4b40-a164-4441-b3cb-182e2a5a5cdb'
    test_name = 'testPrintJpgPhoto'
    logger.info('Print JPG photo in landscape orientation.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['JPG5'],
                              color=self.color, layout='Landscape')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing JPG photo in landscape orientation.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgSingleObject(self):
    test_id = '03a22a19-8089-4150-8f1b-ceb78180713e'
    test_name = 'testPrintJpgSingleObject'
    logger.info('Print JPG file single object in landscape.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['JPG7'],
                              color=self.color, layout='Landscape')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing single object JPG file in landscape.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgProgressive(self):
    test_id = '8ce44d03-ba45-40c5-af0f-2aacb8a6debf'
    test_name = 'testPrintJpgProgressive'
    logger.info('Print a Progressive JPG file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['JPG8'],
                              color=self.color, layout='Landscape')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing progressive JPEG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgMultiImageWithText(self):
    test_id = '2d7ba1af-917b-467b-9e09-72f77cf58a56'
    test_name = 'testPrintJpgMultiImageWithText'
    logger.info('Print multi image with text JPG file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['JPG9'],
                              color=self.color, layout='Landscape')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing multi-image with text JPG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgMaxComplex(self):
    test_id = 'c8208125-e720-406a-9308-bc80d461b08e'
    test_name = 'testPrintJpgMaxComplex'
    logger.info('Print complex JPG file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['JPG10'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing complex JPG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgMultiTargetPortrait(self):
    test_id = '3ff201de-77f3-4be1-9cf2-60dc29698f0b'
    test_name = 'testPrintJpgMultiTargetPortrait'
    logger.info('Print multi-target JPG file with portrait orientation.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['JPG11'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing multi-target JPG file in portrait.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgStepChartLandscape(self):
    test_id = 'f2f2cae4-e835-48e0-8632-953dd50be0ca'
    test_name = 'testPrintJpgStepChartLandscape'
    logger.info('Print step chart JPG file in landscape orientation.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['JPG13'],
                              color=self.color, layout='Landscape')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing step chart JPG file in landscape.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgLarge(self):
    test_id = 'c45e7ebf-241b-4fdf-8d0b-4d7f850a2b1a'
    test_name = 'testPrintJpgLarge'
    logger.info('Print large JPG file with landscape orientation.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['JPG3'],
                              color=self.color, layout='Landscape')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing large JPG file in landscape.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgLargePhoto(self):
    test_id = 'e30fefe9-1a32-4b22-9088-0af5fe2ffd57'
    test_name = 'testPrintJpgLargePhoto'
    logger.info('Print large photo JPG file with landscape orientation.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['JPG4'],
                              color=self.color, layout='Landscape')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing large photo JPG file in landscape.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdf(self):
    """Test a standard, 1 page b&w PDF file."""
    test_id = '0d4d0d33-b170-414d-a722-00e848bede10'
    test_name = 'testPrintFilePdf'
    logger.info('Printing a black and white 1 page PDF file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF4'],
                              color='Monochrome')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing 1 page, black and white PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileColorPdf(self):
    """Test an ICC version 4 test color PDF file."""
    test_id = 'd81fe624-c6ec-4e72-9535-9cead873a4fa'
    test_name = 'testPrintFileColorPdf'
    logger.info('Printing a color, 1 page PDF file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF13'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing 1 page, color PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileMultiPagePdf(self):
    """Test a standard, 3 page color PDF file."""
    test_id = '84e4d761-594d-4930-8a91-b43d037a7422'
    test_name = 'testPrintFileMultiPagePdf'
    logger.info('Printing a 3 page, color PDF file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF10'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing 3 page, color PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileLargeColorPdf(self):
    """Test printing a 20 page, color PDF file."""
    test_id = '005a9954-b55e-40f9-8a66-aa06b5528a78'
    test_name = 'testPrintFileLargeColorPdf'
    logger.info('Printing a 20 page, color PDF file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF1'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing 20 page, color PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfV1_2(self):
    """Test printing PDF version 1.2 file."""
    test_id = '7cd98a62-d209-4d5a-934d-f951e0db9666'
    test_name = 'testPrintFilePdfV1_2'
    logger.info('Printing a PDF v1.2 file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF1.2'])
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing PDF v1.2 file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfV1_3(self):
    """Test printing PDF version 1.3 file."""
    test_id = 'dec3eebc-75b3-47c2-8619-0451e172cb08'
    test_name = 'testPrintFilePdfV1_3'
    logger.info('Printing a PDF v1.3 file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF1.3'])
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing PDF v1.3 file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfV1_4(self):
    """Test printing PDF version 1.4 file."""
    test_id = '881cdd22-49e8-4560-ae13-b8c79741f7d1'
    test_name = 'testPrintFilePdfV1_4'
    logger.info('Printing a PDF v1.4 file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF1.4'])
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing PDF v1.4 file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfV1_5(self):
    """Test printing PDF version 1.5 file."""
    test_id = '518c3a4b-1335-4979-b1e6-2b06acad8905'
    test_name = 'testPrintFilePdfV1_5'
    logger.info('Printing a PDF v1.5 file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF1.5'])
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing PDF v1.5 file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfV1_6(self):
    """Test printing PDF version 1.6 file."""
    test_id = '94dbee8a-e02c-4926-ad7e-a83dbff716dd'
    test_name = 'testPrintFilePdfV1_6'
    logger.info('Printing a PDF v1.6 file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF1.6'])
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing PDF v1.6 file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfV1_7(self):
    """Test printing PDF version 1.7 file."""
    test_id = '2ee12493-eeaf-43cd-a136-d01227d63e9a'
    test_name = 'testPrintFilePdfV1_7'
    logger.info('Printing a PDF v1.7 file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF1.7'])
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing PDF v1.7 file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfColorTicket(self):
    """Test printing PDF file of Color Ticket in landscape orientation."""
    test_id = '4bddcf56-984b-4c4d-9c39-63459b295247'
    test_name = 'testPrintFilePdfColorTicket'
    logger.info('Printing PDF Color ticket in with landscape orientation.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF2'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing color boarding ticket PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfLetterMarginTest(self):
    """Test printing PDF Letter size margin test file."""
    test_id = 'a7328247-84ab-4a8f-865a-f8f30ed20fc2'
    test_name = 'testPrintFilePdfLetterMarginTest'
    logger.info('Printing PDF Letter Margin Test.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF3'])
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing letter margin test PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfMarginTest2(self):
    """Test printing PDF margin test 2 file."""
    test_id = '215a7db8-ae4b-4784-b49a-49c30cf82b53'
    test_name = 'testPrintFilePdfMarginTest2'
    logger.info('Printing PDF Margin Test 2 file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF6'])
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing margin test 2 PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfSimpleLandscape(self):
    """Test printing PDF with landscape layout."""
    test_id = '2aaa222a-7d35-4f88-bfc0-8cf2eb5f8373'
    test_name = 'testPrintFilePdfSimpleLandscape'
    logger.info('Printing simple PDF file in landscape.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF8'],
                              layout='Landscape')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing simple PDF file in landscape.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfCupsTestPage(self):
    """Test printing PDF CUPS test page."""
    test_id = 'ae2a075b-ee7c-409c-8d2d-d08f5c2e868b'
    test_name = 'testPrintFilePdfCupsTestPage'
    logger.info('Printing PDF CUPS test page.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF9'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing CUPS print test PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfColorTest(self):
    """Test printing PDF Color Test file."""
    test_id = '882efbf9-47f2-43cd-9ee9-d4b026679406'
    test_name = 'testPrintFilePdfColorTest'
    logger.info('Printing PDF Color Test page.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF11'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing Color Test PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfBarCodeTicket(self):
    """Test printing Barcoded Ticket PDF file."""
    test_id = 'b38c0113-095e-4e73-8efe-7352852cafb7'
    test_name = 'testPrintFilePdfBarCodeTicket'
    logger.info('Printing PDF Bar coded ticket.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF12'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing bar coded ticket PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfComplexTicket(self):
    """Test printing complex ticket PDF file."""
    test_id = '12555398-4e1f-4305-bcc6-b2b82d665634'
    test_name = 'testPrintFilePdfComplexTicket'
    logger.info('Printing PDF of complex ticket.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PDF14'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing complex ticket that is PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileSimpleGIF(self):
    """Test printing simple GIF file."""
    test_id = '7c346ab2-d8b4-407b-b477-755a0432ace5'
    test_name = 'testPrintFileSimpleGIF'
    logger.info('Printing simple GIF file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['GIF2'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing simple GIF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileSmallGIF(self):
    """Test printing a small GIF file."""
    test_id = '2e81decf-e364-4651-af1b-a516ac51f4bb'
    test_name = 'testPrintFileSmallGIF'
    logger.info('Printing small GIF file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['GIF4'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing small GIF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileLargeGIF(self):
    """Test printing a large GIF file."""
    test_id = '72ed6bc4-1b42-4bc1-921c-4ab205dd56cd'
    test_name = 'testPrintFileLargeGIF'
    logger.info('Printing large GIF file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['GIF1'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing large GIF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileBlackNWhiteGIF(self):
    """Test printing a black & white GIF file."""
    test_id = '7fa69496-542e-4f71-8538-7f67b907a2ec'
    test_name = 'testPrintBlackNWhiteGIF'
    logger.info('Printing black and white GIF file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['GIF3'],
                              color='Monochrome')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing black and white GIF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileHTML(self):
    """Test printing HTML file."""
    test_id = '46164630-7c6e-4b37-b829-5edac13888ac'
    test_name = 'testPrintFileHTML'
    logger.info('Printing HTML file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['HTML1'])
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing HTML file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePngA4Test(self):
    """Test printing A4 Test PNG file."""
    test_id = '4c1e7474-3471-46b2-8e0d-2e605f89c129'
    test_name = 'testPrintFilePngA4Test'
    logger.info('Printing A4 Test PNG file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG1'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing A4 Test PNG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePngPortrait(self):
    """Test printing PNG portrait file."""
    test_id = '7f1e0a95-767e-4302-8225-61d93e127a41'
    test_name = 'testPrintFilePngPortrait'
    logger.info('Printing PNG portrait file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG8'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing PNG portrait file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileColorPngLandscape(self):
    """Test printing color PNG file."""
    test_id = '6b386438-d5cd-46c5-9b25-4ac50faf169c'
    test_name = 'testPrintFileColorPngLandscape'
    logger.info('Printing Color PNG file in landscape.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG2'],
                              color=self.color, layout='Landscape')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing Color PNG in landscape.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileSmallPng(self):
    """Test printing a small PNG file."""
    test_id = '213b84ed-6ddb-4d9b-ab27-be8d5f6d8370'
    test_name = 'testPrintFileSmallPng'
    logger.info('Printing a small PNG file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG3'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing small PNG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePngWithLetters(self):
    """Test printing PNG containing letters."""
    test_id = '83b38406-74f2-4b2e-a74c-54998956ee18'
    test_name = 'testPrintFilePngWithLetters'
    logger.info('Printing PNG file with letters.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG4'],
                              color=self.color, layout='Landscape')
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing PNG file containing letters.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePngColorTest(self):
    """Test printing PNG Color Test file."""
    test_id = '8f66270d-64df-49c7-bb49-01705b65d089'
    test_name = 'testPrintFilePngColorTest'
    logger.info('Printing PNG Color Test file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG5'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing Color Test PNG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePngColorImageWithText(self):
    """Test printing color images with text PNG file."""
    test_id = '931f1994-eebf-4fa6-9549-f8811b4ed641'
    test_name = 'testPrintFilePngColorImageWithText'
    logger.info('Printing color images with text PNG file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG6'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing color images with text PNG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePngCupsTest(self):
    """Test printing Cups Test PNG file."""
    test_id = '055898ba-25f7-4b4b-b116-ff7d499c8994'
    test_name = 'testPrintFilePngCupsTest'
    logger.info('Printing Cups Test PNG file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG7'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing Cups Test PNG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileLargePng(self):
    """Test printing Large PNG file."""
    test_id = '852fab66-af6b-4f06-b94f-9d04508be3c6'
    test_name = 'testPrintFileLargePng'
    logger.info('Printing large PNG file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['PNG9'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing large PNG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileSvgSimple(self):
    """Test printing simple SVG file."""
    test_id = 'f10c0c3c-0d44-440f-8058-a0643235e2f8'
    test_name = 'testPrintFileSvgSimple'
    logger.info('Printing simple SVG file.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['SVG2'])
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing simple SVG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileSvgWithImages(self):
    """Test printing SVG file with images."""
    test_id = '613e3f50-365f-4d4e-be72-d04202f74de4'
    test_name = 'testPrintFileSvgWithImages'
    logger.info('Printing SVG file with images.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['SVG1'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing SVG file with images.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileTiffRegLink(self):
    """Test printing TIFF file of GCP registration link."""
    test_id = 'ff85ffb1-7032-4006-948d-1725d93c5c5a'
    test_name = 'testPrintFileTiffRegLink'
    logger.info('Printing TIFF file of GCP registration link.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['TIFF1'])
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing TIFF file of GCP registration link.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileTiffPhoto(self):
    """Test printing TIFF file of photo."""
    test_id = '983ba7b4-ced0-4144-81cc-6abe89e63f78'
    test_name = 'testPrintFileTiffPhoto'
    logger.info('Printing TIFF file of photo.')
    output = chrome.PrintFile(self.printer, Constants.IMAGES['TIFF2'],
                              color=self.color)
    try:
      self.assertTrue(output)
    except AssertionError:
      notes = 'Error printing TIFF file of photo.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)


if __name__ == '__main__':
  runner = unittest.TextTestRunner(verbosity=2)
  suite = unittest.TestSuite()
  suite.addTest(unittest.makeSuite(SystemUnderTest))
  suite.addTest(unittest.makeSuite(Privet))
  suite.addTest(unittest.makeSuite(PreRegistration))
  suite.addTest(unittest.makeSuite(Registration))
  suite.addTest(unittest.makeSuite(PostRegistration))
  suite.addTest(unittest.makeSuite(LocalDiscovery))
  suite.addTest(unittest.makeSuite(LocalPrinting))
  suite.addTest(unittest.makeSuite(ChromePrinting))
  suite.addTest(unittest.makeSuite(Printer))
  suite.addTest(unittest.makeSuite(PrinterState))
  suite.addTest(unittest.makeSuite(JobState))
  suite.addTest(unittest.makeSuite(Printing))
  suite.addTest(unittest.makeSuite(RunAfter24Hours))
  suite.addTest(unittest.makeSuite(Unregister))
  suite.addTest(unittest.makeSuite(PostUnregister))
  runner.run(suite)
