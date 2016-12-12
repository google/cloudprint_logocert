#!/usr/bin/python

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


The main runner for tests used by the Cloud Print Logo Certification tool.

This suite of tests depends on the unittest runner to execute tests. It will log
results and debug information into a log file.

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
__version__ = '2.0'

import optparse
import platform
import re
import sys
import time
import unittest
import os

from _config import Constants
from _device import Device
import _log
import _mdns
import _oauth2
import _sheets
from _transport import Transport

import httplib2
from oauth2client.client import OAuth2WebServerFlow
from oauth2client.file import Storage
from oauth2client.tools import run_flow
from oauth2client.tools import argparser
from _cpslib import GCPService
from _ticket import CloudJobTicket, CjtConstants

from _common import Sleep
from _common import BlueText
from _common import GreenText
from _common import RedText
from _common import PromptAndWaitForUserAction
from _common import PromptUserAction


# Module level variables
_logger = None
_mdns_browser = None
_transport = None
_device = None
_storage = None
_gcp = None
_sheet = None

def _ParseArgs():
  """Parse command line options."""

  parser = optparse.OptionParser()

  parser.add_option('--autorun',
                    help='Skip manual input',
                    default=Constants.AUTOMODE,
                    action="store_true",
                    dest='autorun')
  parser.add_option('--no-autorun',
                    help='Do not skip manual input',
                    default=Constants.AUTOMODE,
                    action="store_false",
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
  parser.add_option('--if-addr',
                    help='Interface address for Zeroconf',
                    default=None,
                    dest='if_addr')
  parser.add_option('--loadtime',
                    help='Seconds for web pages to load [default: %default]',
                    default=10,
                    type='float',
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
                    default=Constants.PRINTER['NAME'],
                    dest='printer')
  parser.add_option('--no-stdout',
                    help='Do not send output to stdout',
                    default=True,
                    action="store_false",
                    dest='stdout')

  return parser.parse_args()

# The setUpModule will run one time, before any of the tests are run. The global
# keyword must be used in order to give all of the test classes access to
# these objects. This approach is used to eliminate the need for initializing
# all of these objects for each and every test class.
def setUpModule():
  global _logger
  global _mdns_browser
  global _transport
  global _device
  global _storage
  global _gcp

  # Initialize globals and constants
  options, unused_args = _ParseArgs()
  _logger = _log.GetLogger('LogoCert', logdir=options.logdir,
                          loglevel=options.debug, stdout=options.stdout)
  os_type = '%s %s' % (platform.system(), platform.release())
  Constants.TESTENV['OS'] = os_type
  Constants.TESTENV['PYTHON'] = '.'.join(map(str, sys.version_info[:3]))
  _storage = Storage(Constants.AUTH['CRED_FILE'])
  # Retrieve access + refresh tokens
  getTokens()
  _mdns_browser = _mdns.MDnsListener(_logger, options.if_addr)
  _mdns_browser.add_listener('privet')

  # Wait to receive Privet printer advertisements. Timeout in 30 seconds
  found = waitForPrivetDiscovery(options.printer, _mdns_browser)

  if not found:
    _logger.info("No printers discovered under "+ options.printer)
    sys.exit()

  privet_port = None

  for v in _mdns_browser.listener.discovered.values():
    _logger.debug('Found printer in Privet advertisements.')
    if 'ty' in v['info'].properties:
      if options.printer in v['info'].properties['ty']:
        pinfo = str(v['info']).split(',')
        for item in pinfo:
          if 'port' in item:
            privet_port = int(item.split('=')[1])
            _logger.debug('Privet advertises port: %d', privet_port)

  _gcp = GCPService(Constants.AUTH["ACCESS"])
  _device = Device(_logger, Constants.AUTH["ACCESS"], _gcp,
                   privet_port= privet_port if 'PORT' not in Constants.PRINTER else Constants.PRINTER['PORT'])
  _transport = Transport(_logger)

  if Constants.TEST['SPREADSHEET']:
    global _sheet
    _sheet = _sheets.SheetMgr(_logger, _storage.get(), Constants)
    _sheet.MakeHeaders()
  # pylint: enable=global-variable-undefined


def LogTestSuite(name):
  """Log a test result.

  Args:
    name: string, name of the testsuite that is logging.
  """
  print '=============================================================================================================='
  print '                                     Starting %s testSuite'% (name)
  print '=============================================================================================================='
  if Constants.TEST['SPREADSHEET']:
    row = [name,'','','','','','','']
    _sheet.AddRow(row)

def promptForShutDown(device_name):
  """Prompts for the user to turn off the printer.
     Handle different for printers that send Goodbye packets vs those that don't
     Goodbye packets are recommended but not required

      Args:
        device_name: string, printer name
      Returns:
        boolean, True = device is in an off state or confirmed as off by user, False = goodbye packet not seen
      """
  if Constants.CAPS['GOODBYE_PACKET']:
    PromptUserAction('Turn off the printer and wait...')
    return waitForService(device_name, False, timeout=120)
  else:
    PromptAndWaitForUserAction('Press ENTER once printer is powered off')
    # Delete service from zeroconf, so device start up can be polled via mandatory startup packets
    _mdns_browser.clear_cache()
    _mdns_browser.remove_service_entry(device_name)
    return True


def waitForPrivetDiscovery(printer, browser):
  t_end = time.time() + 30

  while time.time() < t_end:
    for v in browser.listener.discovered.values():
      if 'info' in v:
        if 'ty' in v['info'].properties:
          if printer in v['info'].properties['ty']:
            if v['found']:
              return True
    Sleep('POLL')
  # Timed out
  return False


def isPrinterAdvertisingAsRegistered(printer):
  """Checks the printer's privet advertisements and see if it is advertising as registered or not

      Args:
        printer: string, printer name
      Returns:
        boolean, True = advertising as registered, False = advertising as unregistered, None = advertisement not found
      """
  for v in _mdns_browser.listener.discovered.values():
    if 'info' in v:
      if 'ty' in v['info'].properties:
        if printer in v['info'].properties['ty']:
          properties = v['info'].properties
          return properties['id'] and 'online' in properties['cs'].lower()
  return None

def waitForAdvertisementRegistrationStatus(name, is_wait_for_reg, timeout):
  """Wait for the device to privet advertise as registered or unregistered

      Args:
        name: string, device status to wait on
        is_wait_for_reg: boolean, True for registered status, False for unregistered
        timeout: integer, seconds to wait for the service update
      Returns:
        boolean, True = status observed, False = status not observed.
      """
  end = time.time() + timeout
  while time.time() < end:
    is_registered = isPrinterAdvertisingAsRegistered(name)
    if is_registered is is_wait_for_reg:
      return True
    else:
      # Currently, there's no support for device privet updates. When the privet advertisement changes, it
      # doesn't get picked up by the browser even though the browser continuously pings the device.
      # Responses from existing services are dropped therefore we need to remove the service.
      # By removing the service, then waiting for the service to be added again, we get an updated value from the browser
      _mdns_browser.remove_service_entry(_device.name)
      waitForService(_device.name, True, timeout=end-time.time())
  # Time out
  return False

def waitForService(name, is_added, timeout=60):
  """Wait for the mdns listener to add or remove a service

    Args:
      name: string, service name
      is_added: boolean, True for service addition, False for service removal
      timeout: integer, seconds to wait for the service update
    Returns:
      boolean, True = service observed, False = failure to detect service.
    """
  t_start = time.time()
  t_end = t_start + timeout

  while time.time() < t_end:
    queue = _mdns_browser.get_added_q() if is_added else _mdns_browser.get_removed_q()
    while not queue.empty():
      service = queue.get()
      if name in service[0] and t_start < service[1]:
        # the target device is seen to be added/removed
        return True
    Sleep('POLL')
  return False

def getTokens():
  """Retrieve credentials."""
  if 'REFRESH' in Constants.AUTH:
    RefreshToken()
  else:
    creds = _storage.get()
    if creds:
      Constants.AUTH['REFRESH'] = creds.refresh_token
      Constants.AUTH['ACCESS'] = creds.access_token
      RefreshToken()
    else:
      GetNewTokens()


def RefreshToken():
  """Get a new access token with an existing refresh token."""
  response = _oauth2.RefreshToken()
  # If there is an error in the response, it means the current access token
  # has not yet expired.
  if 'access_token' in response:
    _logger.info('Got new access token.')
    Constants.AUTH['ACCESS'] = response['access_token']
  else:
    _logger.info('Using current access token.')


def GetNewTokens():
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
  creds = run_flow(flow, _storage, flags=flags,http=http)

  if creds:
    Constants.AUTH['REFRESH'] = creds.refresh_token
    Constants.AUTH['ACCESS'] = creds.access_token
    RefreshToken()
  else:
    _logger.error('Error getting authorization code.')

def writeRasterToFile(file_path, content):
  """ Save a raster image to file

        Args:
          file_path: string, file path to write to
          content: string, content to write
        """
  f = open(file_path, 'wb')
  f.write(content)
  f.close()

def getRasterImageFromCloud(pwg_path, img_path):
  """ Submit a GCP print job so that the image is coverted to a supported raster file that can be downloaded
      Download the raster image from the cloud then save the raster image to disk

      Args:
        pwg_path: string, destination file path of the pwg_raster image
        img_path: string, src file path of the image to convert from
      """

  #
  cjt = CloudJobTicket(_device.details['gcpVersion'], _device.cdd['caps'])

  print '%s not found. Likely that this is the first time LocalPrinting suite is run.' % (pwg_path)
  print 'Generating pwg-raster via cloud print'
  output = _gcp.Submit(_device.dev_id, img_path, 'LocalPrinting Raster Setup', cjt)
  if not output['success']:
    print 'Cloud printing failed.'
  else:
    print 'Waiting up to 30 seconds for the printer to start printing'
    _device.WaitForPrinterState('processing', timeout=30)

    res = _gcp.FetchRaster(output['job']['id'])
    writeRasterToFile(pwg_path, res)

    print 'Waiting up to 180 seconds for the printer to finish printing'
    _device.WaitForPrinterState('idle', timeout=180)



def getLocalPrintingRasterImages():
  """ Checks to see if the raster images used for local printing exist on the machine,
      generate and store to disk if not
      """
  print "Generating and retrieving pwg-raster images for the LocalPrinting testsuite if they are missing"
  if not os.path.exists(Constants.IMAGES['PWG1']):
    getRasterImageFromCloud(Constants.IMAGES['PWG1'], Constants.IMAGES['PNG7'])

  if not os.path.exists(Constants.IMAGES['PWG2']):
    getRasterImageFromCloud(Constants.IMAGES['PWG2'], Constants.IMAGES['PDF10'])

  if not os.path.exists(Constants.IMAGES['PWG3']):
    getRasterImageFromCloud(Constants.IMAGES['PWG3'], Constants.IMAGES['PNG2'])

class LogoCert(unittest.TestCase):
  """Base Class to drive Logo Certification tests."""

  def shortDescription(self):
    '''Overriding the docstring printout function'''
    doc = self._testMethodDoc
    msg =  doc and doc.split("\n")[0].strip() or None
    return BlueText('\n================'+msg+'================\n\n')


  @classmethod
  def setUpClass(cls, suite=None):
    options, unused_args = _ParseArgs()
    cls.loadtime = options.loadtime
    cls.username = options.email
    cls.pw = options.passwd
    cls.autorun = options.autorun
    cls.printer = options.printer

    cls.monochrome = CjtConstants.MONOCHROME
    cls.color = CjtConstants.COLOR if Constants.CAPS['COLOR'] else cls.monochrome

    suite_name = cls.__name__ if suite is None else suite.__name__
    LogTestSuite(suite_name)


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
      Sleep('AUTO_RUN')
      return True
    print 'Did the test produce the expected result?'
    result = PromptAndWaitForUserAction('Enter "y" or "n"')
    try:
      self.assertEqual(result.lower(), 'y')
    except AssertionError:
      notes = PromptAndWaitForUserAction('Type in additional notes for test failure, hit return when finished')
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
    failure = False if result.lower() in ['passed','skipped'] else True

    console_result = RedText(result) if failure else GreenText(result)
    console_test_name = RedText(test_name) if failure else GreenText(test_name)

    _logger.info('test_id: %s: %s', test_id, console_result)
    _logger.info('%s: %s', test_id, console_test_name)
    if notes:
      console_notes = RedText(notes) if failure else GreenText(notes)
      _logger.info('%s: Notes: %s', test_id, console_notes)
    else:
      notes = ''
    if Constants.TEST['SPREADSHEET']:
      row = [str(test_id), test_name, result, notes,'','','']
      if failure:
        # If failed, generate the commandline that the user could use to rerun this testcase
        module = os.path.basename(sys.argv[0]).split('.')[0] # get module name - name of this python script
        testsuite = sys._getframe(1).f_locals['self'].__class__.__name__ # get the class name of the caller
        row.append('python -m unittest %s.%s.%s' %(module,testsuite,test_name))
      _sheet.AddRow(row)


  @classmethod
  def GetDeviceDetails(cls):
    _device.GetDeviceDetails()
    if not _device.name:
      _logger.error('Error finding device in GCP MGT page.')
      _logger.error('Check printer model in _config file.')
      raise unittest.SkipTest('Could not find device on GCP MGT page.')
    else:
      _logger.debug('Printer name: %s', _device.name)
      _logger.debug('Printer status: %s', _device.status)
      for k in _device.details:
        _logger.debug(k)
        _logger.debug(_device.details[k])
        _logger.debug('===============================')
      _device.GetDeviceCDD(_device.dev_id)
      for k in _device.cdd:
        _logger.debug(k)
        _logger.debug(_device.cdd[k])
        _logger.debug('===============================')


class SystemUnderTest(LogoCert):
  """Record details about the system under test and test environment."""

  def testRecordTestEnv(self):
    """Record test environment details."""
    test_id = '5e5e44cd-4e37-4f16-b1ec-1874912c7449'
    test_name = 'testRecordTestEnv'
    notes = 'Android: %s\n' % Constants.TESTENV['ANDROID']
    notes += 'Tablet: %s\n' % Constants.TESTENV['TABLET']

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
      self.assertIn('x-privet-token', _device.privet_info)
    except AssertionError:
      notes = 'No x-privet-token found. Error in privet info API.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'X-Privet-Token: %s' % _device.privet_info['x-privet-token']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoAPIManufacturer(self):
    """Verify device PrivetInfo API contains manufacturer field."""
    test_id = '0da3de50-2541-4585-8314-d3593be7a2d9'
    test_name = 'testPrivetInfoAPIManufacturer'
    # When a device object is initialized, it sends a request to the privet
    # info API, so all of the needed information should already be set.
    try:
      self.assertIn('manufacturer', _device.privet_info)
    except AssertionError:
      notes = 'manufacturer not found in privet info.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Manufacturer: %s' % _device.privet_info['manufacturer']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoAPIModel(self):
    """Verify device PrivetInfo API contains model field."""
    test_id = 'd2725e0d-033a-45b2-b528-cb00f8729e5b'
    test_name = 'testPrivetInfoAPIModel'
    # When a device object is initialized, it sends a request to the privet
    # info API, so all of the needed information should already be set.
    try:
      self.assertIn('model', _device.privet_info)
    except AssertionError:
      notes = 'model not found in privet info.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Model: %s' % _device.privet_info['model']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoAPIFirmware(self):
    """Verify device PrivetInfo API contains firmware field."""
    test_id = '9ab29ed3-cbed-458e-9cd7-0021c1da37d2'
    test_name = 'testPrivetInfoAPIFirmware'
    # When a device object is initialized, it sends a request to the privet
    # info API, so all of the needed information should already be set.
    try:
      self.assertIn('firmware', _device.privet_info)
    except AssertionError:
      notes = 'firmware not found in privet info.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Firmware: %s' % _device.privet_info['firmware']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoAPIUpdateUrl(self):
    """Verify device PrivetInfo API contains update_url field."""
    test_id = 'd7f67d75-9f9d-49ad-b3b2-5557c8c51470'
    test_name = 'testPrivetInfoAPIUpdateUrl'
    # When a device object is initialized, it sends a request to the privet
    # info API, so all of the needed information should already be set.
    try:
      self.assertIn('update_url', _device.privet_info)
    except AssertionError:
      notes = 'update_url not found in privet info.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'update_url: %s' % _device.privet_info['update_url']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoAPIVersion(self):
    """Verify device PrivetInfo API contains version field."""
    test_id = 'daef86f2-f979-4960-8d57-677ce2b237d7'
    test_name = 'testPrivetInfoAPIVersion'
    # When a device object is initialized, it sends a request to the privet
    # info API, so all of the needed information should already be set.
    valid_versions = ['1.0', '1.1', '1.5', '2.0']
    try:
      self.assertIn('version', _device.privet_info)
    except AssertionError:
      notes = 'version not found in privet info.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertIn(_device.privet_info['version'], valid_versions)
      except AssertionError:
        notes = 'Incorrect GCP Version in privetinfo: %s' % (
            _device.privet_info['version'])
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Version: %s' % _device.privet_info['version']
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoDeviceState(self):
    """Verify device PrivetInfo API contains DeviceState and valid value."""
    test_id = '3d0fdb69-d14c-4628-a45d-54048465f741'
    test_name = 'testPrivetInfoDeviceState'
    valid_states = ['idle', 'processing', 'stopped']
    try:
      self.assertIn('device_state', _device.privet_info)
    except AssertionError:
      notes = 'device_state not found in privet info.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertIn(_device.privet_info['device_state'], valid_states)
      except AssertionError:
        notes = 'Incorrect device_state in privet info: %s' % (
            _device.privet_info['device_state'])
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Device state: %s' % _device.privet_info['device_state']
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoConnectionState(self):
    """Verify device PrivetInfo contains ConnectionState and valid value."""
    test_id = '2f4b5912-fa44-4e37-b4a5-01cd2ea7fcfc'
    test_name = 'testPrivetInfoConnectionState'
    valid_states = ['online', 'offline', 'connecting', 'not-configured']
    try:
      self.assertIn('connection_state', _device.privet_info)
    except AssertionError:
      notes = 'connection_state not found in privet info.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertIn(_device.privet_info['connection_state'], valid_states)
      except AssertionError:
        notes = 'Incorrect connection_state in privet info: %s' % (
            _device.privet_info['connection_state'])
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Connection state: %s' % _device.privet_info['connection_state']
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetAccessTokenAPI(self):
    """Verify unregistered device Privet AccessToken API returns correct rc."""
    test_id = '74b0548c-5932-4aaa-a363-56dd9d44268b'
    test_name = 'testPrivetAccessTokenAPI'
    api = 'accesstoken'
    return_code = [200, 404]
    response = _transport.HTTPReq(_device.privet_url[api], headers=_device.headers)
    try:
      self.assertIsNotNone(response['code'])
    except AssertionError:
      notes = 'No response received from %s' % _device.privet_url[api]
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertIn(response['code'], return_code)
      except AssertionError:
        notes = 'Incorrect return code, found %d' % response['code']
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = '%s returned response code %d' % (_device.privet_url[api],
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
    response = _transport.HTTPReq(_device.privet_url[api], headers=_device.headers)
    try:
      self.assertIsNotNone(response['code'])
    except AssertionError:
      notes = 'No response received from %s' % _device.privet_url[api]
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertEqual(response['code'], return_code)
      except AssertionError:
        notes = 'Incorrect return code from %s, found %d' % (_device.privet_url[api],response['code'])
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = '%s returned code %d' % (_device.privet_url[api],
                                         response['code'])
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetPrinterAPI(self):
    """Verify unregistered device Privet Printer API returns correct rc."""
    test_id = 'c6e56ee1-eb55-478b-a495-dbdfeb7fe1ae'
    test_name = 'testPrivetPrinterAPI'
    api = 'printer'
    return_code = [200, 404]
    response = _transport.HTTPReq(_device.privet_url[api], headers=_device.headers)
    try:
      self.assertIsNotNone(response['code'])
    except AssertionError:
      notes = 'No response received from %s' % _device.privet_url[api]
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertIn(response['code'], return_code)
      except AssertionError:
        notes = 'Incorrect return code, found %d' % response['code']
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = '%s returned code %d' % (_device.privet_url[api],
                                         response['code'])
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetUnknownURL(self):
    """Verify device returns 404 return code for unknown url requests."""
    test_id = 'caf2f4e7-df0d-4093-8303-73eff5ab9024'
    test_name = 'testPrivetUnknownURL'
    response = _transport.HTTPReq(_device.privet_url['INVALID'],
                                 headers=_device.headers)
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

    success = _device.StartPrivetRegister()
    try:
      self.assertTrue(success)
    except AssertionError:
      notes = 'Error starting privet registration.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      notes = 'Privet registration API working correctly'
      self.LogTest(test_id, test_name, 'Passed', notes)
      # Cancel the registration so the printer is not in an unknown state
      _device.CancelRegistration()

  def testPrivetRegistrationInvalidParam(self):
    """Verify device return error if invalid registration param given."""
    test_id = 'fec798b2-ed5f-44ac-8752-e44fd47462e2'
    test_name = 'testPrivetRegistrationInvalidParam'
    response = _transport.HTTPReq(
        _device.privet_url['register']['invalid'], data='',
        headers=_device.headers, user=Constants.USER['EMAIL'])
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
        notes = 'Response code from invalid registration params: %d' % (
            response['code'])
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        try:
          self.assertIn('error', response['data'])
        except AssertionError:
          notes = 'Did not find error message. Error message: %s' % (
            response['data'])
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        else:
          notes = 'Received correct error code and response: %d\n%s' % (
            response['code'], response['data'])
          self.LogTest(test_id, test_name, 'Passed', notes)
        finally:
          _device.CancelRegistration()

  def testPrivetInfoAPIEmptyToken(self):
    """Verify device returns code 200 if Privet Token is empty."""
    test_id = '9cce6158-7b68-42b3-94b2-9bacadac07c9'
    test_name = 'testPrivetInfoAPIEmptyToken'
    response = _transport.HTTPReq(_device.privet_url['info'],
                                 headers=_device.privet.headers_empty)
    try:
      self.assertIsNotNone(response['code'])
    except AssertionError:
      notes = 'No response code received.'
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
    response = _transport.HTTPReq(_device.privet_url['info'],
                                 headers=_device.privet.headers_invalid)
    try:
      self.assertIsNotNone(response['code'])
    except AssertionError:
      notes = 'No response code received.'
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
    response = _transport.HTTPReq(_device.privet_url['info'],
                                 headers=_device.privet.headers_missing)
    try:
      self.assertIsNotNone(response['code'])
    except AssertionError:
      notes = 'No response code received.'
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
    """Verify a device will not register if the claim token is invalid."""
    test_id = 'a48518b0-bc96-480b-a8f2-f26cbb42e1b8'
    test_name = 'testDeviceRegistrationInvalidClaimToken'
    try:
      self.assertTrue(_device.StartPrivetRegister())
    except AssertionError:
      notes = 'Error starting privet registration.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      try:
        print 'Accept the registration request on the device.'
        PromptAndWaitForUserAction('Press ENTER once registration accepted.')
        Sleep('REGISTRATION')
        try:
          self.assertTrue(_device.GetPrivetClaimToken())
        except AssertionError:
          notes = 'Error getting claim token.'
          self.LogTest(test_id, test_name, 'Blocked', notes)
          raise
        else:
          _device.automated_claim_url = (
              'https://www.google.com/cloudprint/confirm?token=INVALID')
          try:
            self.assertFalse(_device.SendClaimToken(Constants.AUTH['ACCESS']))
          except AssertionError:
            notes = 'Device accepted invalid claim token.'
            self.LogTest(test_id, test_name, 'Failed', notes)
            raise
          else:
            notes = 'Device did not accept invalid claim token.'
            self.LogTest(test_id, test_name, 'Passed', notes)
      finally:
        _device.CancelRegistration()

  def testDeviceRegistrationInvalidUserAuthToken(self):
    """Verify a device will not register if the user auth token is invalid."""
    test_id = 'da3d4ce4-5b81-4bb4-a487-7c8e92b552c6'
    test_name = 'testDeviceRegistrationInvalidUserAuthToken'
    try:
      self.assertTrue(_device.StartPrivetRegister())
    except AssertionError:
      notes = 'Error starting privet registration.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      try:
        print 'Accept the registration request on the device.'
        print 'Note: some printers may not show a registration request.'
        PromptAndWaitForUserAction('Press ENTER once registration is accepted.')
        Sleep('REGISTRATION')
        try:
          self.assertTrue(_device.GetPrivetClaimToken())
        except AssertionError:
          notes = 'Error getting claim token.'
          self.LogTest(test_id, test_name, 'Blocked', notes)
          raise
        else:
          try:
            self.assertFalse(_device.SendClaimToken('INVALID_USER_AUTH_TOKEN'))
          except AssertionError:
            notes = 'Claim token accepted with invalid User Auth Token.'
            self.LogTest(test_id, test_name, 'Failed', notes)
            raise
          else:
            notes = 'Claim token not accepted with invalid user auth token.'
            self.LogTest(test_id, test_name, 'Passed', notes)
      finally:
        _device.CancelRegistration()


class Printer(LogoCert):
  """Verify printer provides necessary details."""

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass(cls)
    LogoCert.GetDeviceDetails()

  def testPrinterName(self):
    """Verify printer provides a name."""
    test_id = '79f45999-b9e7-4f95-8992-79c06eaa1b76'
    test_name = 'testPrinterName'
    try:
      self.assertIsNotNone(_device.name)
    except AssertionError:
      notes = 'No printer name found.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      _logger.info('Printer name found in details.')
    try:
      self.assertIn(Constants.PRINTER['MODEL'], _device.name)
    except AssertionError:
      notes = 'Model not in name. Found %s' % _device.name
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('name', _device.cdd)
    except AssertionError:
      notes = 'Printer CDD missing printer name.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      _logger.info('Printer name found in CDD.')
    try:
      self.assertIn(Constants.PRINTER['MODEL'], _device.cdd['name'])
    except AssertionError:
      notes = 'Model not in name. Found %s in CDD' % _device.cdd['name']
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Printer name: %s' % _device.name
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterStatus(self):
    """Verify printer has online status."""
    test_id = 'f04dfb47-5745-498b-b366-c79d37536904'
    test_name = 'testPrinterStatus'
    try:
      self.assertIsNotNone(_device.status)
    except AssertionError:
      notes = 'Device has no status.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('ONLINE', _device.status)
    except AssertionError:
      notes = 'Device is not online. Status: %s' % _device.status
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Status: %s' % _device.status
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterModel(self):
    """Verify printer provides a model string."""
    test_id = '145f1c07-0e9d-4a5e-ae17-ff31f62c94e3'
    test_name = 'testPrinterModel'
    try:
      self.assertIn('model', _device.details)
    except AssertionError:
      notes = 'Model is missing from the printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn(Constants.PRINTER['MODEL'], _device.details['model'])
    except AssertionError:
      notes = 'Model incorrect, printer details: %s' % _device.details['Model']
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('model', _device.cdd)
    except AssertionError:
      notes = 'Model is missing from the printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn(Constants.PRINTER['MODEL'], _device.cdd['model'])
    except AssertionError:
      notes = 'Printer model has unexpected value. Found %s' % (
          _device.cdd['model'])
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Model: %s' % _device.details['model']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterManufacturer(self):
    """Verify printer provides a manufacturer string."""
    test_id = '68134ba3-5a05-4a77-82ca-b06ae6195cd8'
    test_name = 'testPrinterManufacturer'
    try:
      self.assertIn('manufacturer', _device.details)
    except AssertionError:
      notes = 'Manufacturer in not set in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn(Constants.PRINTER['MANUFACTURER'],
                    _device.details['manufacturer'])
    except AssertionError:
      notes = 'Manufacturer is not in printer details. Found %s' % (
          _device.details['Manufacturer'])
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('manufacturer', _device.cdd)
    except AssertionError:
      notes = 'Manufacturer is not set in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn(Constants.PRINTER['MANUFACTURER'],
                    _device.cdd['manufacturer'])
    except AssertionError:
      notes = 'Manufacturer not found in printer CDD. Found %s' % (
          _device.cdd['manufacturer'])
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Manufacturer: %s' % _device.details['manufacturer']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterSerialNumber(self):
    """Verify printer provides a serial number."""
    test_id = '3996db1d-93ea-4f4c-b70c-dfd9355d5e5d'
    test_name = 'testPrinterSerialNumber'
    try:
      self.assertIn('uuid', _device.details)
    except AssertionError:
      notes = 'Serial number not found in device details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(_device.details['uuid']), 1)
    except AssertionError:
      notes = 'Serial number does is not valid number.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Serial Number: %s' % _device.details['uuid']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterGCPVersion(self):
    """Verify printer provides GCP Version supported."""
    test_id = '7a8ec212-52d2-441d-8e18-383ac850f567'
    test_name = 'testPrinterGCPVersion'
    try:
      self.assertIn('gcpVersion', _device.details)
    except AssertionError:
      notes = 'GCP Version not found in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertEqual('2.0', _device.details['_gcpVersion'])
    except AssertionError:
      notes = 'Version 2.0 not found in GCP Version support. Found %s' % (
          _device.details['Google Cloud Print Version'])
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('gcpVersion', _device.cdd)
    except AssertionError:
      notes = 'GCP Version not found in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertEqual('2.0', _device.cdd['gcpVersion'])
    except AssertionError:
      notes = 'Version 2.0 not found in GCP Version. Found %s' % (
          _device.cdd['gcpVersion'])
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'GCP Version: %s' % _device.details['gcpVersion']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterFirmwareVersion(self):
    """Verify printer provides a firmware version."""
    test_id = '96b2fc8d-708d-4be8-b439-7fec563c44d9'
    test_name = 'testPrinterFirmwareVersion'
    try:
      self.assertIn('firmware', _device.details)
    except AssertionError:
      notes = 'Firmware version is missing in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(_device.details['firmware']), 1)
    except AssertionError:
      notes = 'Firmware version is not correctly identified.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('firmware', _device.cdd)
    except AssertionError:
      notes = 'Firmware version is missing in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(_device.cdd['firmware']), 1)
    except AssertionError:
      notes = 'Firmware version is not correctly identified in CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Firmware version: %s' % _device.details['firmware']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterType(self):
    """Verify printer provides a type."""
    test_id = 'f4fb09a4-527b-4fa7-8629-0171037db113'
    test_name = 'testPrinterType'
    try:
      self.assertIn('type', _device.details)
    except AssertionError:
      notes = 'Printer Type not found in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('GOOGLE', _device.details['type'])
    except AssertionError:
      notes = 'Incorrect Printer Type in details. Found %s' % (
          _device.details['PrinterType'])
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('type', _device.cdd)
    except AssertionError:
      notes = 'Printer Type not found in printer CDD'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('GOOGLE', _device.cdd['type'])
    except AssertionError:
      notes = 'Incorrect Printer Type in CDD. Found %s' % _device.cdd['type']
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Printer Type: %s' % _device.details['type']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterFirmwareUpdateUrl(self):
    """Verify printer provides a firmware update URL."""
    test_id = '27a06940-2f82-4550-8231-69615aa516c8'
    test_name = 'testPrinterFirmwareUpdateUrl'
    try:
      self.assertIn('updateUrl', _device.details)
    except AssertionError:
      notes = 'Firmware update url not found in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(
          _device.details['updateUrl']), 10)
    except AssertionError:
      notes = 'Firmware Update URL is not valid in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('updateUrl', _device.cdd)
    except AssertionError:
      notes = 'Firmware update Url not found in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(_device.cdd['updateUrl']), 10)
    except AssertionError:
      notes = 'Firmware Update URL is not valid in CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Firmware Update URL: %s' % (
          _device.details['updateUrl'])
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterProxy(self):
    """Verify that printer provides a proxy."""
    test_id = 'd01c84fd-6310-47f0-a464-60997a8e3d68'
    test_name = 'testPrinterProxy'
    try:
      self.assertIn('proxy', _device.details)
    except AssertionError:
      notes = 'Proxy not found in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(_device.details['proxy']), 1)
    except AssertionError:
      notes = 'Proxy is not valid value.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('proxy', _device.cdd)
    except AssertionError:
      notes = 'Proxy not found in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(_device.cdd['proxy']), 1)
    except AssertionError:
      notes = 'Proxy is not valid value.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Printer Proxy: %s' % _device.details['proxy']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testSetupUrl(self):
    """Verify the printer provides a setup URL."""
    test_id = 'd03c034d-2deb-42d9-a6fd-1685c2472e97'
    test_name = 'testSetupUrl'
    try:
      self.assertIn('setupUrl', _device.cdd)
    except AssertionError:
      notes = 'Setup URL not found in CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(_device.cdd['setupUrl']), 10)
    except AssertionError:
      notes = 'Setup URL is not a valid. Found %s' % _device.cdd['setupUrl']
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Setup URL: %s' % _device.cdd['setupUrl']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterID(self):
    """Verify Printer has a PrinterID."""
    test_id = '5bc5d513-3a1f-441a-8acd-d007fe0e0e35'
    test_name = 'testPrinterID'
    try:
      self.assertIsNotNone(_device.dev_id)
    except AssertionError:
      notes = 'Printer ID not found in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(_device.dev_id), 10)
    except AssertionError:
      notes = 'Printer ID is not valid in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('id', _device.cdd)
    except AssertionError:
      notes = 'Printer ID not found in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(_device.cdd['id']), 10)
    except AssertionError:
      notes = 'Printer ID is not valid in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Printer ID: %s' % _device.dev_id
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testLocalSettings(self):
    """Verify the printer contains local settings."""
    test_id = 'cede3eec-41fb-43de-b1f1-76d17443b6f3'
    test_name = 'testLocalSettings'
    try:
      self.assertIn('local_settings', _device.cdd)
    except AssertionError:
      notes = 'local_settings not found in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertIn('current', _device.cdd['local_settings'])
    except AssertionError:
      notes = 'No current settings found in local_settings.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Local settings: %s' % _device.cdd['local_settings']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCaps(self):
    """Verify the printer contains capabilities."""
    test_id = '1977ab77-27af-4702-a6f3-5b66fc1b5720'
    test_name = 'testCaps'
    try:
      self.assertIn('caps', _device.cdd)
    except AssertionError:
      notes = 'No capabilities found in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(_device.cdd['caps']), 10)
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
      self.assertIn('uuid', _device.cdd)
    except AssertionError:
      notes = 'uuid not found in printer CDD.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertGreaterEqual(len(_device.cdd['uuid']), 1)
    except AssertionError:
      notes = 'uuid is not a valid value.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'UUID: %s' % _device.cdd['uuid']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testDefaultDisplayName(self):
    """Verify Default Display Name is present."""
    test_id = '1cb52261-cf01-45ed-b447-8ec8902b36f2'
    test_name = 'testDefaultDisplayName'
    try:
      self.assertIn('defaultDisplayName', _device.cdd)
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
      self.assertIn('supported_content_type', _device.cdd['caps'])
    except AssertionError:
      notes = 'supported_content_type missing from printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    content_types = []
    for item in _device.cdd['caps']['supported_content_type']:
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
          _device.cdd['caps']['supported_content_type'])
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsPwgRasterConfig(self):
    """Verify printer CDD contains a pwg_raster_config parameter."""
    test_id = 'e3565806-2320-48ef-8eab-2f48fbcffc33'
    test_name = 'testCapsPwgRasterConfig'
    try:
      self.assertIn('pwg_raster_config', _device.cdd['caps'])
    except AssertionError:
      notes = 'pwg_raster_config parameter not found in printer cdd.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'pwg_raster_config: %s' % (
          _device.cdd['caps']['pwg_raster_config'])
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsInputTrayUnit(self):
    """Verify input_tray_unit is in printer capabilities."""
    test_id = 'e10b7314-fc04-4a4a-ae59-8bf4a3ae165d'
    test_name = 'testCapsInputTrayUnit'
    try:
      self.assertIn('input_tray_unit', _device.cdd['caps'])
    except AssertionError:
      notes = 'input_tray_unit not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'input_tray_unit: %s' % _device.cdd['caps']['input_tray_unit']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsOutputBinUnit(self):
    """Verify output_bin_unit is in printer capabilities."""
    test_id = '0f329dba-75c3-45f0-a3a1-4d63f5d195b0'
    test_name = 'testCapsOutputBinUnit'
    try:
      self.assertIn('output_bin_unit', _device.cdd['caps'])
    except AssertionError:
      notes = 'output_bin_unit not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'output_bin_unit: %s' % _device.cdd['caps']['output_bin_unit']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsMarker(self):
    """Verify marker is in printer capabilities."""
    test_id = '35005c07-3b18-48b2-a3a2-20fe78bedff2'
    test_name = 'testCapsMarker'
    try:
      self.assertIn('marker', _device.cdd['caps'])
    except AssertionError:
      notes = 'marker not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'marker: %s' % _device.cdd['caps']['marker']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsCover(self):
    """Verify cover is in printer capabilities."""
    test_id = 'c5564d8b-d811-4510-b031-b761bb094631'
    test_name = 'testCapsCover'
    try:
      self.assertIn('cover', _device.cdd['caps'])
    except AssertionError:
      notes = 'cover not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'cover: %s' % _device.cdd['caps']['cover']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsColor(self):
    """Verify color is in printer capabilities."""
    test_id = '01bd068d-0b8f-41a4-82ea-39ef5fb09994'
    test_name = 'testCapsColor'
    try:
      self.assertIn('color', _device.cdd['caps'])
    except AssertionError:
      notes = 'color not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'color: %s' % _device.cdd['caps']['color']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsDuplex(self):
    """Verify duplex is in printer capabilities."""
    test_id = '7bda6263-a629-4e1a-84e9-28e84fa2b014'
    test_name = 'testCapsDuplex'
    try:
      self.assertIn('duplex', _device.cdd['caps'])
    except AssertionError:
      notes = 'duplex not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'duplex: %s' % _device.cdd['caps']['duplex']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsCopies(self):
    """Verify copies is in printer capabilities."""
    test_id = '9d1464d1-46fb-4d1c-a8fb-3fa0e7dc9509'
    test_name = 'testCapsCopies'
    if not Constants.CAPS['COPIES_CLOUD']:
      self.LogTest(test_id, test_name, 'Skipped', 'Copies not supported')
      return
    try:
      self.assertIn('copies', _device.cdd['caps'])
    except AssertionError:
      notes = 'copies not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'copies: %s' % _device.cdd['caps']['copies']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsDpi(self):
    """Verify dpi is in printer capabilities."""
    test_id = 'cd4c9dbc-da9d-4de7-a5b7-74e4618ce1b7'
    test_name = 'testCapsDpi'
    try:
      self.assertIn('dpi', _device.cdd['caps'])
    except AssertionError:
      notes = 'dpi not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'dpi: %s' % _device.cdd['caps']['dpi']
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsMediaSize(self):
    """Verify media_size is in printer capabilities."""
    test_id = 'dae470da-ac50-47cb-8ef7-073cc856cfed'
    test_name = 'testCapsMediaSize'
    try:
      self.assertIn('media_size', _device.cdd['caps'])
    except AssertionError:
      notes = 'media_size not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'media_size: %s' % _device.cdd['caps']['media_size']
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
      self.assertIn('collate', _device.cdd['caps'])
    except AssertionError:
      notes = 'collate not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'collate: %s' % _device.cdd['caps']['collate']
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
        self.assertNotIn('page_orientation', _device.cdd['caps'])
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
      self.assertNotIn('margins', _device.cdd['caps'])
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
      self.assertNotIn('fit_to_page', _device.cdd['caps'])
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
      self.assertNotIn('page_range', _device.cdd['caps'])
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
      self.assertNotIn('reverse_order', _device.cdd['caps'])
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
      self.assertIn('capsHash', _device.cdd)
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
      self.assertIn('certificationId', _device.cdd)
    except AssertionError:
      notes = 'certificationId not found in printer capabilities.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertEqual(Constants.PRINTER['CERTID'],
                         _device.cdd['certificationId'])
      except AssertionError:
        notes = 'Certification ID: %s, expected %s' % (
            _device.cdd['certificationId'], Constants.PRINTER['CERTID'])
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Certification ID: %s' % _device.cdd['certificationId']
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testCapsResolvedIssues(self):
    """Verify printer contains resolvedIssues in printer capabilities."""
    test_id = '5a1ef1e7-26ba-458b-a72f-a5ebf26e437c'
    test_name = 'testCapsResolvedIssues'
    try:
      self.assertIn('resolvedIssues', _device.cdd)
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
    LogoCert.setUpClass(cls)
    cls.sleep_time = 60


  def testDeviceAdvertisePrivet(self):
    """Verify printer under test advertises itself using Privet."""
    test_id = '3382acca-15f7-46d1-9b43-2d36defa9443'
    test_name = 'testDeviceAdvertisePrivet'

    print 'Listening for the printer\'s advertisements for up to 60 seconds'
    _mdns_browser.remove_service_entry(_device.name)
    success = waitForService(_device.name, True)
    try:
      self.assertTrue(success)
    except AssertionError:
      notes = 'Device is not found advertising in privet'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      is_registered = isPrinterAdvertisingAsRegistered(_device.name)
      try:
        self.assertFalse(is_registered)
      except AssertionError:
        notes = 'Device is advertising as a registered device'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Device is advertising as an unregistered device'
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testDeviceSleepingAdvertisePrivet(self):
    """Verify sleeping printer advertises itself using Privet."""
    test_id = 'fffb765b-bb62-4927-82d4-209928ef7d23'
    test_name = 'testDeviceSleepingAdvertisePrivet'

    print 'Put the printer in sleep mode.'
    PromptAndWaitForUserAction('Press ENTER when printer is sleeping.')

    print 'Listening for the printer\'s advertisements for up to 60 seconds'
    _mdns_browser.remove_service_entry(_device.name)
    success = waitForService(_device.name, True)
    try:
      self.assertTrue(success)
    except AssertionError:
      notes = 'Device is not found advertising in privet'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      is_registered = isPrinterAdvertisingAsRegistered(_device.name)
      try:
        self.assertFalse(is_registered)
      except AssertionError:
        notes = 'Device not found advertising as a registered device in sleep mode'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Device is found advertising as an unregistered device in sleep mode'
        self.LogTest(test_id, test_name, 'Passed', notes)


  def testDeviceOffNoAdvertisePrivet(self):
    """Verify powered off device does not advertise using Privet."""
    test_id = '35ce7a3d-3403-499e-9a60-4d17e1693178'
    test_name = 'testDeviceOffNoAdvertisePrivet'

    is_off = promptForShutDown(_device.name)
    try:
      self.assertTrue(is_off)
    except AssertionError:
      notes = 'Error receiving the shutdown signal from the printer.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    print 'Listening for the printer\'s advertisements for up to 60 seconds'
    _mdns_browser.remove_service_entry(_device.name)
    found = waitForService(_device.name, True)

    try:
      self.assertFalse(found)
    except AssertionError:
      notes = 'Device found advertising when powered off'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Device no longer advertising when powered off'
      self.LogTest(test_id, test_name, 'Passed', notes)

      """Verify freshly powered on device advertises itself using Privet."""
      test_id2 = 'ad3c730b-dcc9-4597-8953-d9bc5dca4205'
      test_name2 = 'testDeviceOffPowerOnAdvertisePrivet'
      # Clear global browser cache before turning on the device, or else the stale printer state will be returned
      _mdns_browser.clear_cache()
      PromptUserAction('Power on the printer and wait...')
      is_added = waitForService(_device.name, True, timeout=300)
      try:
        self.assertTrue(is_added)
      except AssertionError:
        notes = 'Error receiving the power-on signal from the printer.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise

      print 'Listening for the printer\'s advertisements for up to 60 seconds'
      _mdns_browser.remove_service_entry(_device.name)
      success = waitForService(_device.name, True)
      try:
        self.assertTrue(success)
      except AssertionError:
        notes = 'Device is not found advertising in privet when freshly powered on'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        is_registered = isPrinterAdvertisingAsRegistered(_device.name)
        try:
          self.assertFalse(is_registered)
        except AssertionError:
          notes = 'Device found advertising as registered when freshly powered on'
          self.LogTest(test_id2, test_name2, 'Failed', notes)
          raise
        else:
          notes = 'Device found advertising as unregistered when freshly powered on'
          self.LogTest(test_id2, test_name2, 'Passed', notes)
        finally:
          # Get the new X-privet-token from the restart
          _device.GetPrivetInfo()

  def testDeviceRegistrationNotLoggedIn(self):
    """Test printer cannot be registered if user not logged in."""
    test_id = '984be779-3ca4-4bb7-a2e1-e1868f687905'
    test_name = 'testDeviceRegistrationNotLoggedIn'

    success = _device.Register('Press ENTER after confirming registration', use_token=False)
    try:
      self.assertFalse(success)
    except AssertionError:
      notes = 'Able to register printer without an auth token.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Not able to register printer without a valid auth token.'
      self.LogTest(test_id, test_name, 'Passed', notes)
      # Cancel the registration so the printer is not in an unknown state
      _device.CancelRegistration()


  def testDeviceCancelRegistration(self):
    """Test printer cancellation prevents registration."""
    test_id = 'ce1c9c46-3164-4f07-aa41-241867a4a28b'
    test_name = 'testDeviceCancelRegistration'
    _logger.info('Testing printer registration cancellation.')

    print 'Testing printer registration cancellation.'
    print 'Do not accept printer registration request on printer panel.'

    registration_success = _device.Register('Press ENTER after CANCELLING the registration on the printer')
    if not registration_success:
      # Confirm the user's account has no registered printers
      res = _gcp.Search(_device.model)
      try:
        # Assert that 'printers' list is empty
        self.assertFalse(res['printers'])
      except AssertionError:
        notes = 'Unable to cancel registration request.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Cancelled registration attempt from printer panel.'
        self.LogTest(test_id, test_name, 'Passed', notes)
    else:
      notes = 'Error cancelling registration process.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      _device.CancelRegistration()

  def testLocalPrintGuestUserUnregisteredPrinter(self):
    """Verify local print for unregistered printer is correct."""
    test_id = '6e75edff-2512-4c7b-b5f0-79d2ef17d922'
    test_name = 'testLocalPrintGuestUserUnregisteredPrinter'
    return
    # New instance of device that is not authenticated - contains no auth-token
    guest_device = Device(_logger, None, None, privet_port=_device.port)
    guest_device.GetDeviceCDDLocally()

    cjt = CloudJobTicket(guest_device.privet_info['version'], guest_device.cdd['caps'])

    job_id = guest_device.LocalPrint(test_name, Constants.IMAGES['PWG1'], cjt)
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Guest failed to print a page via local printing on the unregistered printer.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
    else:
      print 'Guest successfully printed a page via local printing on the unregistered printer.'
      print 'If not, fail this test.'
      self.ManualPass(test_id, test_name)


class Registration(LogoCert):
  """Test device registration."""

  def testDeviceRegistration(self):
    """Verify printer registration using Privet

    This test function actually executes three tests.
    1- Printer UI timeout after registration results in cancellation
    2- User2 cannot register after User1 has begun registration process
    3- User1 successfully registers
    """
    test_id = 'b36f4085-f14f-49e0-adc0-cdbaae45bd9f'
    test_name = 'testDeviceRegistration'
    test_id2 = '64f31b27-0779-4c94-8f8a-ec9d44ce6171'
    test_name2 = 'testDeviceRegistrationNoAccept'
    print 'Do not select accept/cancel registration from the printer U/I.'
    print 'Wait for the registration request to time out.'

    # Timeout test
    success = _device.StartPrivetRegister()
    if success:
      PromptAndWaitForUserAction('Press ENTER once the printer registration times out.')
      Sleep('REGISTRATION')
      # Confirm the user's account has no registered printers
      res = _gcp.Search(_device.model)
      try:
        self.assertFalse(res['printers'])
      except AssertionError:
        notes = 'Not able to cancel printer registration from printer UI timeout.'
        self.LogTest(test_id2, test_name2, 'Failed', notes)
        raise
      else:
        notes = 'Printer registration cancelled from printer UI timeout.'
        self.LogTest(test_id2, test_name2, 'Passed', notes)
    else:
      notes = 'Not able to initiate printer registration.'
      self.LogTest(test_id2, test_name2, 'Failed', notes)
      raise

    # Register user1
    success = _device.StartPrivetRegister(user=Constants.USER['EMAIL'])
    try:
      self.assertTrue(success)
    except AssertionError:
      notes = 'Not able to register user1.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      _device.CancelRegistration(user=Constants.USER['EMAIL'])
      raise
    else:
      success = _device.Register('User2 Registration attempt',
                                user=Constants.USER2['EMAIL'], no_wait=True)
      try:
        self.assertFalse(success)
      except AssertionError:
        notes = 'Simultaneous registration succeeded.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        PromptUserAction('Now accept the registration request from %s on the printer UI.' % Constants.USER['EMAIL'])
        PromptAndWaitForUserAction('Press ENTER once the registration is accepted.');
        Sleep('REGISTRATION')

        # Finish the registration process
        success = False
        if _device.GetPrivetClaimToken():
          if _device.ConfirmRegistration(_device.auth_token):
            _device.FinishPrivetRegister()
            success = True
        try:
          self.assertTrue(success)
        except AssertionError:
          notes = 'User1 failed to register.'
          self.LogTest(test_id, test_name, 'Failed', notes)
          _device.CancelRegistration()
          raise
        else:
          print 'Waiting up to 2 minutes to complete the registration.'
          success = waitForAdvertisementRegistrationStatus(_device.name, True, 120)
          try:
            self.assertTrue(success)
          except AssertionError:
            notes = 'Registered device not found advertising or found advertising as unregistered'
            self.LogTest(test_id, test_name, 'Failed', notes)
            raise
          else:
            res = _gcp.Search(_device.model)
            try:
              self.assertTrue(res['printers'])
            except AssertionError:
              notes = 'Not able to register printer under user.'
              self.LogTest(test_id, test_name, 'Failed', notes)
              raise
            else:
              notes = 'Registered printer'
              self.LogTest(test_id, test_name, 'Passed', notes)


class LocalDiscovery(LogoCert):
  """Tests Local Discovery functionality."""

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass(cls)
    LogoCert.GetDeviceDetails()

  def testLocalDiscoveryToggle(self):
    """Verify printer respects GCP Mgt page when local discovery toggled."""
    test_id = '54131136-9e03-4b17-acd2-7ca72e2ad732'
    test_name = 'testLocalDiscoveryToggle'
    notes = None
    notes2 = None

    setting = {'pending': {'local_discovery': False}}
    res = _gcp.Update(_device.dev_id, setting=setting)

    if not res['success']:
      notes = 'Error turning off Local Discovery.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    # Give printer time to update.
    print 'Waiting up to 120 seconds for printer to accept changes.'
    # Wait for the service to be removed as local_discovery gets disabled
    # Could use waitForUpdate() also, but might as well wait for the printer
    # state to populate properly before moving on
    success = waitForService(_device.name, False, timeout=120)

    try:
      self.assertTrue(success)
    except AssertionError:
      notes = 'Local Discovery was not disabled within the allotted time.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      notes = 'Local Discovery successfully disabled'

      setting = {'pending': {'local_discovery': True}}
      res = _gcp.Update(_device.dev_id, setting=setting)
      if not res['success']:
        notes2 = 'Error turning on Local Discovery.'
        self.LogTest(test_id, test_name, 'Blocked', notes + '\n' + notes2)
        raise

      # Give printer time to update.
      print 'Waiting up to 120 seconds for printer to accept changes.'
      success = waitForService(_device.name, True, timeout=120)

      try:
        self.assertTrue(success)
      except AssertionError:
        notes2 = 'Local Discovery was not enabled within the allotted time.'
        self.LogTest(test_id, test_name, 'Blocked', notes + '\n' + notes2)
        raise
      else:
        notes2 = 'Local Discovery successfully enabled'
        notes = notes + '\n' + notes2
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterOnAdvertiseLocally(self):
    """Verify printer advertises self using Privet when turned on."""
    test_id = 'e979119e-5a35-4065-89cf-1c4ef795c5b9'
    test_name = 'testPrinterOnAdvertiseLocally'
    printer_found = False

    print 'This test should begin with the printer turned off.'
    is_off = promptForShutDown(_device.name)
    try:
      self.assertTrue(is_off)
    except AssertionError:
      notes = 'Error receiving the shutdown signal from the printer.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    PromptUserAction('Power on the printer and wait...')
    is_added = waitForService(_device.name, True, timeout=300)
    try:
      self.assertTrue(is_added)
    except AssertionError:
      notes = 'Error receiving the power-on signal from the printer.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    # Get the new X-privet-token from the restart
    _device.GetPrivetInfo()

    for v in _mdns_browser.listener.discovered.values():
      if 'ty' in v['info'].properties:
        if self.printer in v['info'].properties['ty']:
          printer_found = True
          try:
            self.assertTrue(v['found'])
          except AssertionError:
            notes = 'Printer did not broadcast privet packet.'
            self.LogTest(test_id, test_name, 'Failed', notes)
            raise
          else:
            notes = 'Printer broadcast privet packet.'
    if not printer_found:
      notes = 'Printer did not make privet packet.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterOffSendGoodbyePacket(self):
    """Verify printer sends goodbye packet when turning off."""
    test_id = '074cf049-a13c-4a7e-91ed-a0ce9457b4f4'
    test_name = 'testPrinterOffSendGoodbyePacket'
    failed = False
    printer_found = False

    print 'This test must start with the printer on and operational.'
    is_off = promptForShutDown(_device.name)
    try:
      self.assertTrue(is_off)
    except AssertionError:
      notes = 'Error receiving the shutdown signal from the printer.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    for v in _mdns_browser.listener.discovered.values():
      if 'ty' in v['info'].properties:
        if self.printer in v['info'].properties['ty']:
          printer_found = True
          try:
            self.assertFalse(v['found'])
            break
          except AssertionError:
            failed = True
    if not printer_found:
      failed = True

    if failed:
      notes = 'Printer did not send goodbye packet when powered off.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Printer sent goodbye packet when powered off.'
      self.LogTest(test_id, test_name, 'Passed', notes)

    PromptUserAction('Power on the printer and wait...')
    is_added = waitForService(_device.name, True, timeout=300)
    try:
      self.assertTrue(is_added)
    except AssertionError:
      notes = 'Error receiving the power-on signal from the printer.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise


  def testPrinterIdleNoBroadcastPrivet(self):
    """Verify idle printer doesn't send mDNS broadcasts."""
    test_id = '703a55d2-7291-4637-b257-dc885fdb5abd'
    test_name = 'testPrinterIdleNoBroadcastPrivet'

    print 'Ensure printer stays on and remains in idle state.'
    # Service TTL should not be updated if there are no advertisements from the idle printer
    # Only exception is if the last record's TTL expires, then the service browser's
    # queries will exclude the printer service's answer in it's constant polls, prompting
    # the printer to respond with an advertisement, so power off and power on the printer
    # to get a fresh TTL
    start_ttl = _mdns_browser.get_service_ttl(_device.name)

    if start_ttl < 60:
      # Force restart for corner cases where TTL might expire
      is_off = promptForShutDown(_device.name)
      try:
        self.assertTrue(is_off)
      except AssertionError:
        notes = 'Error receiving the shutdown signal from the printer.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        # Need to clear the cache of zeroconf, or else the stale printer details will be returned
        _mdns_browser.clear_cache()
        PromptUserAction('Power on the printer and wait...')
        is_added = waitForService(_device.name, True, timeout=300)
        try:
          self.assertTrue(is_added)
        except AssertionError:
          notes = 'Error receiving the power-on signal from the printer.'
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        else:
          # Get the new X-privet-token from the restart
          _device.GetPrivetInfo()
          start_ttl = _mdns_browser.get_service_ttl(_device.name)

    # Monitor the local network for privet broadcasts.
    print 'Listening for network broadcasts for 60 seconds.'
    time.sleep(60)
    end_ttl = _mdns_browser.get_service_ttl(_device.name)

    try:
      self.assertTrue(start_ttl > end_ttl)
    except AssertionError:
      notes = 'Found printer mDNS broadcast packets containing privet while printer is idle.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'No printer mDNS broadcast packets containing privet were found while printer is idle.'
      self.LogTest(test_id, test_name, 'Passed', notes)


  def testUpdateLocalSettings(self):
    """Verify printer's local settings can be updated with Update API."""
    test_id = '9a2fde45-ea02-4cdd-90ab-af752cbdd394'
    test_name = 'testUpdateLocalSettings'
    # Get the current xmpp timeout value.

    orig = _device.cdd['local_settings']['current']['xmpp_timeout_value']
    new = orig + 600
    setting = {'pending': {'xmpp_timeout_value': new}}
    res = _gcp.Update(_device.dev_id, setting=setting)

    if not res['success']:
      notes = 'Error sending Update of local settings.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise

    print 'Waiting up to 30 seconds for printer to accept pending settings'
    try:
      success = _gcp.WaitForUpdate(_device.dev_id, 'xmpp_timeout_value', new)
      self.assertTrue(success)
    except AssertionError:
      notes = 'Failed to detect update before timing out.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      # Refresh the values of the device.
      _device.GetDeviceCDD(_device.dev_id)
      timeout = _device.cdd['local_settings']['current']['xmpp_timeout_value']
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
        setting = {'pending': {'xmpp_timeout_value': orig}}
        res = _gcp.Update(_device.dev_id, setting=setting)
        try:
          self.assertTrue(res['success'])
        except AssertionError:
          notes = 'Error sending Update of local settings.'
          self.LogTest(test_id, test_name, 'Blocked', notes)
          raise


class LocalPrinting(LogoCert):
  """Tests of local printing functionality."""
  def setUp(self):
    # Create a fresh CJT for each test case
    self.cjt = CloudJobTicket(_device.privet_info['version'], _device.cdd['caps'])

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass(cls)
    LogoCert.GetDeviceDetails()

    # Need to download a few raster files that will be used to test local printing
    # Different printers support different pwg-raster resolution and colours
    # Leverage GCP conversion by submitting a cloud print tickets, then downloading
    # the raster files and saving them to disk
    getLocalPrintingRasterImages()

  def testLocalPrintGuestUser(self):
    """Verify local print on a registered printer is available to guest user."""
    test_id = '8ba6f1ba-66cc-4d9e-aa3c-1d2e611ddb38'
    test_name = 'testLocalPrintGuestUser'

    # New instance of device that is not authenticated - contains no auth-token
    guest_device = Device(_logger, None, None, privet_port=_device.port)
    guest_device.GetDeviceCDDLocally()

    job_id = guest_device.LocalPrint(test_name, Constants.IMAGES['PWG1'], self.cjt)
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Guest failed to print a page via local printing.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
    else:
      print 'Guest successfully printed a page via local printing.'
      print 'If not, fail this test.'
      self.ManualPass(test_id, test_name)

  def testLocalPrintingToggle(self):
    """Verify printer respects GCP Mgt page when local printing toggled."""
    test_id = '533d4ac6-5c1d-4c99-a91e-2bac7c31864f'
    test_name = 'testLocalPrintingToggle'
    notes = None
    notes2 = None

    print 'Disabling local printing'
    setting = {'pending': {'printer/local_printing_enabled': False}}
    res = _gcp.Update(_device.dev_id, setting=setting)

    if not res['success']:
      notes = 'Error turning off Local Printing.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise

    # Give the printer time to update.
    print 'Waiting up to 30 seconds for printer to accept pending settings'
    try:
      success = _gcp.WaitForUpdate(_device.dev_id, 'printer/local_printing_enabled', False)
      self.assertTrue(success)
    except AssertionError:
      notes = 'Failed to detect update before timing out.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG1'], self.cjt)
    try:
      self.assertIsNone(job_id)
    except AssertionError:
      notes = 'Able to print via privet local printing when disabled.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      notes = 'Not able to print locally when disabled.'

    print 'Re-enabling local printing'
    setting = {'pending': {'printer/local_printing_enabled': True}}
    res = _gcp.Update(_device.dev_id, setting=setting)

    if not res['success']:
      notes2 = 'Error turning on Local Printing.'
      self.LogTest(test_id, test_name, 'Blocked', notes2)
      raise

    # Give the printer time to update.
    print 'Waiting up to 30 seconds for printer to accept pending settings'
    try:
      success = _gcp.WaitForUpdate(_device.dev_id, 'printer/local_printing_enabled', True)
      self.assertTrue(success)
    except AssertionError:
      notes = 'Failed to detect update before timing out.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG1'], self.cjt)
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes2 = 'Not able to print locally when enabled.'
      self.LogTest(test_id, test_name, 'Blocked', notes2)
      raise
    else:
      notes2 = 'Able to print via privet local printing when re-enabled.'
      self.LogTest(test_id, test_name, 'Passed', notes + '\n' + notes2)



  def testLocalPrintTwoSided(self):
    """Verify printer respects two-sided option in local print."""
    test_id = 'e235f70d-2f81-4ea4-9d0d-b56db2174a57'
    test_name = 'testLocalPrintTwoSided'

    if not Constants.CAPS['DUPLEX']:
      self.LogTest(test_id, test_name, 'Skipped', 'No Duplex support')
      return

    self.cjt.AddDuplexOption(CjtConstants.LONG_EDGE)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG2'], self.cjt)
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error printing with duplex in local printing.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    print 'Verify print job is printed in duplex.'
    self.ManualPass(test_id, test_name)


  def testLocalPrintMargins(self):
    """Verify printer respects margins selected in local print."""
    test_id = 'f0143e4e-8dc1-42c1-96da-b9abc39a0b8e'
    test_name = 'testLocalPrintMargins'

    if not Constants.CAPS['MARGIN']:
      self.LogTest(test_id, test_name, 'Skipped', 'No Margin support')
      return

    self.cjt.AddMarginOption(CjtConstants.BORDERLESS, 0, 0, 0, 0)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG1'], self.cjt)
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing with no margins.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    self.cjt.AddMarginOption(CjtConstants.STANDARD, 50, 50, 50, 50)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG1'], self.cjt)
    try:
      self.assertIsNotNone(job_id)
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
    test_name = 'testLocalPrintLayoutPortrait'

    #TODO: Do we still care about this???
    #  When the Chrome issue of local printing page layout is fixed, this
    #  code should be removed.
    if not Constants.CAPS['LAYOUT_ISSUE']:
      notes = 'Printer does not have the workaround for the Chrome issue.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return

    self.cjt.AddPageOrientationOption(CjtConstants.PORTRAIT)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG3'], self.cjt)
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing with portrait layout.'
      self.LogTest(test_id, test_name, 'Blocked', notes)

    print 'The print job should be printed in portrait layout.'
    print 'If the layout is not correct, fail this test.'
    self.ManualPass(test_id, test_name)

    test_id2 = '3be1b5e6-cc96-417c-a131-ef96b0576c21'
    test_name2 = 'testLocalPrintLayoutLandscape'

    self.cjt.AddPageOrientationOption(CjtConstants.LANDSCAPE)
    job_id = _device.LocalPrint(test_name2, Constants.IMAGES['PWG3'], self.cjt)
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing with landscape layout.'
      self.LogTest(test_id2, test_name2, 'Blocked', notes)

    print 'The print job should be printed in landscape layout.'
    print 'If the layout is not correct, fail this test.'
    self.ManualPass(test_id2, test_name2)

  def testLocalPrintPageRange(self):
    """Verify printer respects page range in local print."""
    test_id = '1580f47d-4115-462d-b85e-bd4d5fd4d7e3'
    test_name = 'testLocalPrintPageRange'

    self.cjt.AddPageRangeOption(2,3)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG2'], self.cjt)
    try:
      self.assertIsNotNone(job_id)
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

    if not Constants.CAPS['COPIES_LOCAL']:
      notes = 'Printer does not support copies option.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return

    self.cjt.AddCopiesOption(2)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG1'], self.cjt)
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing with copies option.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
    else:
      print 'The print job should have printed 2 copies.'
      print 'If 2 copies are not printed, fail this test.'
      self.ManualPass(test_id, test_name)

  def testLocalPrintColorSelect(self):
    """Verify printer respects color option in local print."""
    test_id = '7e0e555f-d8ac-4ec3-b268-0420baf14684'
    test_name = 'testLocalPrintColorSelect'

    if not Constants.CAPS['COLOR']:
      notes = 'Printer does not support color printing.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return

    self.cjt.AddColorOption(CjtConstants.COLOR)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG1'], self.cjt)
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing with color selected.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
    else:
      print 'Print job should be printed in color.'
      print 'If not, fail this test.'
      self.ManualPass(test_id, test_name)

    test_id2 = '553fbcb6-0d98-45a4-a0d7-308297852135'
    test_name2 = 'testLocalPrintMonochromeSelect'

    self.cjt.AddColorOption(CjtConstants.MONOCHROME)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG1'], self.cjt)
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing with monochrome selected.'
      self.LogTest(test_id2, test_name2, 'Blocked', notes)
    else:
      print 'Print job should be printed in monochrome.'
      print 'If not, fail this test.'
      self.ManualPass(test_id2, test_name2)

  def testLocalPrintUpdateMgtPage(self):
    """Verify printer jobstate API is functional."""
    test_id = '530c74f7-2764-405e-916b-21fc943ea1f8'
    test_name = 'testLocalPrintUpdateMgtPage'
    #TODO: not tested yet, need a printer that supports this
    if '/privet/printer/jobstate' not in _device.privet_info['api']:
      notes = 'Printer does not support the jobstate privet API.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG1'], self.cjt)
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing %s' % Constants.IMAGES['PWG1']
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      # Give the printer time to complete the job and update the status.
      PromptAndWaitForUserAction('Press ENTER once the document id printed')
      print 'Waiting 30 seconds for job to print and status to be updated.'
      time.sleep(30) # Determine if this is needed after testing a printer that supports Privet Info API
      job = _device.JobState(job_id)
      try:
        self.assertIsNotNone(job)
      except AssertionError:
        notes = 'Failed to retrieve status of the print job via privet'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        try:
          self.assertIn('done', job['state'])
        except AssertionError:
          notes = 'Printjob was not updated as done.'
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        else:
          notes = 'Printjob was updated as completed.'
          self.LogTest(test_id, test_name, 'Passed', notes)

  def testLocalPrintHTML(self):
    """Verify printer can local print HTML file."""
    test_id = '8745d54b-045a-4378-a024-d331785ac62e'
    test_name = 'testLocalPrintHTML'

    if 'text/html' not in _device.supported_types:
      self.LogTest(test_id, test_name, 'Skipped', 'No local print Html support')
      return

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['HTML1'], self.cjt)
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing %s' % Constants.IMAGES['HTML1']
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

    if 'image/jpeg' not in _device.supported_types and \
       'image/pjpeg' not in _device.supported_types:
      self.LogTest(test_id, test_name, 'Skipped', 'No local print Jpg support')
      return

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['JPG12'], self.cjt)
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing %s' % Constants.IMAGES['JPG12']
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

    if 'image/png' not in _device.supported_types:
      self.LogTest(test_id, test_name, 'Skipped', 'No local print PNG support')
      return

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PNG6'], self.cjt)
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing %s' % Constants.IMAGES['PNG6']
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

    if 'image/gif' not in _device.supported_types:
      self.LogTest(test_id, test_name, 'Skipped', 'No local print Gif support')
      return

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['GIF4'], self.cjt)
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing %s' % Constants.IMAGES['GIF4']
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

    if 'application/pdf' not in _device.supported_types:
      self.LogTest(test_id, test_name, 'Skipped', 'No local print PDF support')
      return

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PDF9'], self.cjt)
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing %s' % Constants.IMAGES['PDF9']
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'PDF file should be printed.'
      print 'Fail this test if print out has errors or quality issues.'
      self.ManualPass(test_id, test_name)


class PostRegistration(LogoCert):
  """Tests to run after _device is registered."""

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass(cls)
    LogoCert.GetDeviceDetails()

  def testDeviceDetails(self):
    """Verify printer details are provided to Cloud Print Service."""
    test_id = '6bcf8903-af2c-439c-9c8b-1dd829521905'
    test_name = 'testDeviceDetails'

    try:
      self.assertIsNotNone(_device.name)
    except AssertionError:
      notes = 'Error finding device in GCP MGT Page.'
      self._logger.error('Check your printer model in the _config file.')
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Found printer details on GCP MGT page.'
      _device.GetDeviceCDD(_device.dev_id)
      self.LogTest(test_id, test_name, 'Passed', notes)


  def testRegisteredDevicePoweredOffShowsOffline(self):
    """Verify device shows offline when it is powered off."""
    test_id = 'ba6b2c0c-10da-4910-bb6f-63c826087054'
    test_name = 'testRegisteredDevicePoweredOffShowsOffline'

    is_off = promptForShutDown(_device.name)
    try:
      self.assertTrue(is_off)
    except AssertionError:
      notes = 'Error receiving the shutdown signal from the printer.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print'Waiting up to 10 minutes for printer status update. Polling every 30 seconds.'
      end = time.time() + 600
      while time.time() < end:
        _device.GetDeviceDetails()
        if 'OFFLINE' in _device.status:
          break
        time.sleep(30) # Not using Constant.SLEEP['POLL'] here since the status update actually takes a while
      try:
        self.assertIsNotNone(_device.status)
      except AssertionError:
        notes = 'Device has no status.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      try:
        self.assertIn('OFFLINE', _device.status)
      except AssertionError:
        notes = 'Device is not offline. Status: %s' % _device.status
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Status: %s' % _device.status
        self.LogTest(test_id, test_name, 'Passed', notes)
      finally:
        PromptUserAction('Power on the printer and wait...')
        is_added = waitForService(_device.name, True, timeout=300)
        try:
          self.assertTrue(is_added)
        except AssertionError:
          notes = 'Error receiving the power-on signal from the printer.'
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        # Get the new X-privet-token from the restart
        _device.GetPrivetInfo()

  def testRegisteredDeviceNotDiscoverableAfterPowerOn(self):
    """Verify power cycled registered device does not advertise using Privet."""
    test_id = '7e4ce6cd-0ad1-4194-83f7-3ea11fa30526'
    test_name = 'testRegisteredDeviceNotDiscoverableAfterPowerOn'

    is_off = promptForShutDown(_device.name)
    try:
      self.assertTrue(is_off)
    except AssertionError:
      notes = 'Error receiving the shutdown signal from the printer.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      # Need to clear the cache of zeroconf, or else the stale printer details will be returned
      _mdns_browser.clear_cache()
      PromptUserAction('Power on the printer and wait...')
      is_added = waitForService(_device.name, True, timeout=300)
      try:
        self.assertTrue(is_added)
      except AssertionError:
        notes = 'Error receiving the power-on signal from the printer.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        # Get the new X-privet-token from the restart
        _device.GetPrivetInfo()
        is_registered = isPrinterAdvertisingAsRegistered(self.printer)
        try:
          self.assertTrue(is_registered)
        except AssertionError:
          notes = 'Printer is advertising as an unregistered device'
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        else:
          notes = 'Printer is advertising as a registered device.'
          self.LogTest(test_id, test_name, 'Passed', notes)


class PrinterState(LogoCert):
  """Test that printer state is reported correctly."""

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass(cls)
    LogoCert.GetDeviceDetails()

  def VerifyUiStateMessage(self, test_id, test_name, keywords_list, suffixes = None):
    """Verify state messages.

    Args:
      test_id: integer, testid in TestTracker database.
      test_name: string, name of test.
      keywords_list: array, list of strings that should be found in the uiState.
                    each element in the array is looked for in the UI state
                    elements can be slash separated for aliasing where only
                    one term of the slash separated string needs to match.
                    ie. ['door/cover', 'open']
      suffixes: tuple or string, additional allowed suffixes of uiState messages
    Returns:
      boolean: True = Pass, False = Fail.
    """
    if 'uiState' in _device.cdd:
      if 'caption' in _device.cdd['uiState']:
        uiMsg = _device.cdd['uiState']['caption'].lower()
        uiMsg = re.sub(r' \(.*\)$', '', uiMsg)
        uiMsg.strip()
      else:
        notes = 'No \'caption\' attribute found inside uiState'
        self.LogTest(test_id, test_name, 'Failed', notes)
        return False

    found = False
    # check for keywords
    for keywords in keywords_list:
      found = False
      for keyword in keywords.split('/'):
        if keyword.lower() in uiMsg:
          found = True
          break
      if not found:
        break

    if found and suffixes is not None:
      #check for suffixes
      found = False
      if uiMsg.endswith(suffixes):
        found = True

    if found:
      self.LogTest(test_id, test_name, 'Passed')
      return True
    else:
      notes = 'required keyword(s) "%s" not in UI state message' % keywords
      self.LogTest(test_id, test_name, 'Failed', notes)
      return False

  def VerifyUiStateHealthy(self, test_id, test_name):
    """Verify ui state has no error messages.

    Args:
      test_id: integer, testid in TestTracker database.
      test_name: string, name of test.
    Returns:
      boolean: True = Pass, False = Fail.
    """
    is_healthy = False if 'caption' in _device.cdd['uiState'] else True

    if is_healthy:
      self.LogTest(test_id, test_name, 'Passed')
      return True
    else:
      notes = 'UI shows error state with message: %s' % _device.cdd['uiState']['caption']
      self.LogTest(test_id, test_name, 'Failed', notes)
      return False

  def testLostNetworkConnection(self):
    """Verify printer that loses network connection reconnects properly."""
    test_id = '0af4301e-bacb-40c4-8b95-a8b29aefc8dd'
    test_name = 'testLostNetworkConnection'

    print 'Test printer handles connection status when reconnecting to network.'
    PromptAndWaitForUserAction('Press ENTER once printer loses network connection.')
    Sleep('NETWORK_DETECTION')
    print 'Now reconnect printer to the network.'
    PromptAndWaitForUserAction('Press ENTER once printer has network connection.')
    Sleep('NETWORK_DETECTION')
    _device.GetDeviceDetails()
    try:
      self.assertIn('ONLINE', _device.status)
    except AssertionError:
      notes = 'Device status is not online.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Device status is online.'
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testOpenPaperTray(self):
    """Verify if open paper tray is reported correctly."""
    test_id = '519969fa-97d1-4116-84e7-4f1f689e1df7'
    test_name = 'testOpenPaperTray'

    if not Constants.CAPS['TRAY_SENSOR']:
      notes = 'Printer does not have paper tray sensor.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    print 'Open the paper tray to the printer.'
    PromptAndWaitForUserAction('Press ENTER once the paper tray is open.')
    Sleep('PRINTER_STATE')
    _device.GetDeviceDetails()
    try:
      self.assertTrue(_device.error_state or _device.warning_state)
    except AssertionError:
      notes = 'Printer is not in error state with open paper tray.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      # Check state message. Some input trays may not be opened and be normally empty.
      if not self.VerifyUiStateMessage(test_id, test_name, ['input/tray'], suffixes=('is open', 'is empty', '% full')):
        raise

    test_id2 = '5041f9a4-0b58-451a-906f-dec2375d93a4'
    test_name2 = 'testClosedPaperTray'
    print 'Now close the paper tray.'
    PromptAndWaitForUserAction('Press ENTER once the paper tray is closed.')
    Sleep('PRINTER_STATE')
    _device.GetDeviceDetails()
    try:
      self.assertFalse(_device.error_state or _device.warning_state)
    except AssertionError:
      notes = 'Paper tray is closed but printer reports error.'
      self.LogTest(test_id2, test_name2, 'Failed', notes)
      raise
    else:
      if not self.VerifyUiStateHealthy(test_id2, test_name2):
        raise

  def testNoMediaInTray(self):
    """Verify no media in paper tray reported correctly."""
    test_id = 'e8001a2a-e403-4f5a-94e5-59e61528d161'
    test_name = 'testNoMediaInTray'

    if not Constants.CAPS['MEDIA_SENSOR']:
      notes = 'Printer does not have a paper tray sensor.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    print 'Remove all media from the paper tray.'
    PromptAndWaitForUserAction('Press ENTER once all media is removed.')
    Sleep('PRINTER_STATE')
    _device.GetDeviceDetails()
    if not self.VerifyUiStateMessage(test_id, test_name, ['input/tray'],suffixes=('is empty')):
      raise

    test_id2 = '64e592be-d6c4-424e-9e69-021c92b09953'
    test_name2 = 'testMediaInTray'
    print 'Place media in all paper trays.'
    PromptAndWaitForUserAction('Press ENTER once you have placed paper in paper tray.')
    Sleep('PRINTER_STATE')
    _device.GetDeviceDetails()
    if not self.VerifyUiStateHealthy(test_id2, test_name2):
      raise

  def testRemoveTonerCartridge(self):
    """Verify missing/empty toner cartridge is reported correctly."""
    test_id = '3be1a76e-b60f-4166-aeb2-0feed9de67c8'
    test_name = 'testRemoveTonerCartridge'

    if not Constants.CAPS['TONER']:
      notes = 'Printer does not contain ink toner.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return True
    print 'Remove the (or one) toner cartridge from the printer.'
    PromptAndWaitForUserAction('Press ENTER once the toner cartridge is removed.')
    Sleep('PRINTER_STATE')
    _device.GetDeviceDetails()
    try:
      self.assertTrue(_device.error_state)
    except AssertionError:
      notes = 'Printer is not in error state with missing toner cartridge.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      if not self.VerifyUiStateMessage(test_id, test_name, ['int/toner'], ('is removed', 'is empty', 'is low', 'pages remaining', '%')):
        raise

    test_id2 = 'b73b5b6b-9398-48ad-9646-dbb501b32f8c'
    test_name2 = 'testExhaustTonerCartridge'
    print 'Insert an empty toner cartridge in printer.'
    PromptAndWaitForUserAction('Press ENTER once an empty toner cartridge is in printer.')
    Sleep('PRINTER_STATE')
    _device.GetDeviceDetails()
    try:
      self.assertTrue(_device.error_state)
    except AssertionError:
      notes = 'Printer is not in error state with empty toner.'
      self.LogTest(test_id2, test_name2, 'Failed', notes)
      raise
    else:
      if not self.VerifyUiStateMessage(test_id2, test_name2, ['int/toner'], ('is removed', 'is empty', 'is low', 'pages remaining', '%')):
        raise

    test_id3 = 'e2a57ebb-97cf-4f36-b405-0d753d4a862c'
    test_name3 = 'testReplaceMissingToner'
    print 'Verify that the error is fixed by replacing the original toner cartridge.'
    PromptAndWaitForUserAction('Press ENTER once toner is replaced in printer.')
    Sleep('PRINTER_STATE')
    _device.GetDeviceDetails()
    try:
      self.assertFalse(_device.error_state)
    except AssertionError:
      notes = 'Printer is in error state with good toner cartridge.'
      self.LogTest(test_id3, test_name3, 'Failed', notes)
      raise
    else:
      if not self.VerifyUiStateHealthy(test_id3, test_name3):
        raise

  def testCoverOpen(self):
    """Verify that an open door or cover is reported correctly."""
    test_id = 'b4d4f888-2a97-4ab4-aab8-c847046616f8'
    test_name = 'testCoverOpen'

    if not Constants.CAPS['COVER']:
      notes = 'Printer does not have a cover.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    print 'Open a cover on your printer.'
    PromptAndWaitForUserAction('Press ENTER once the cover has been opened.')
    Sleep('PRINTER_STATE')
    _device.GetDeviceDetails()
    try:
      self.assertTrue(_device.error_state)
    except AssertionError:
      notes = 'Printer is not in error state with open cover.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      if not self.VerifyUiStateMessage(test_id, test_name, ['Door/Cover'], suffixes=('is open')):
        raise

    test_id2 = 'a26b7d34-15b4-4819-84a5-4b8e5bc3a30e'
    test_name2 = 'testCoverClosed'
    print 'Now close the printer cover.'
    PromptAndWaitForUserAction('Press ENTER once the printer cover is closed.')
    Sleep('PRINTER_STATE')
    _device.GetDeviceDetails()
    try:
      self.assertFalse(_device.error_state)
    except AssertionError:
      notes = 'Printer is in error state with closed cover.'
      self.LogTest(test_id2, test_name2, 'Failed', notes)
      raise
    else:
      if not self.VerifyUiStateHealthy(test_id2, test_name2):
        raise

  def testPaperJam(self):
    """Verify printer properly reports a paper jam with correct state."""
    test_id = 'fe089b80-0e1b-4f28-9239-42b8d65724ac'
    test_name = 'testPaperJam'

    print 'Cause the printer to become jammed with paper.'
    PromptAndWaitForUserAction('Press ENTER once the printer has become jammed.')
    Sleep('PRINTER_STATE')
    _device.GetDeviceDetails()
    try:
      self.assertTrue(_device.error_state)
    except AssertionError:
      notes = 'Printer is not in error state with paper jam.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      if not self.VerifyUiStateMessage(test_id, test_name, ['paper jam']):
        raise

    test_id2 = 'ff7e0f11-4955-4510-8a5c-91f809f6b263'
    test_name2 = 'testRemovePaperJam'
    print 'Now clear the paper jam.'
    PromptAndWaitForUserAction('Press ENTER once the paper jam is clear from printer.')
    Sleep('PRINTER_STATE')
    _device.GetDeviceDetails()
    try:
      self.assertFalse(_device.error_state)
    except AssertionError:
      notes = 'Printer is in error after paper jam was cleared.'
      self.LogTest(test_id2, test_name2, 'Failed', notes)
      raise
    else:
      if not self.VerifyUiStateHealthy(test_id2, test_name2):
        raise


class JobState(LogoCert):
  """Test that print jobs are reported correctly from the printer."""
  def setUp(self):
    # Create a fresh CJT for each test case
    self.cjt = CloudJobTicket(_device.details['gcpVersion'], _device.cdd['caps'])
    self.timeout = 600

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass(cls)
    LogoCert.GetDeviceDetails()

  def testOnePagePrintJobState(self):
    """Verify a 1 page print job is reported correctly."""
    test_id = '345f2083-ec94-4548-9c01-ad7d8f1840ec'
    test_name = 'testOnePagePrintJobState'
    print 'Wait for this one page print job to finish.'

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['JPG6'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing one page JPG file.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      try:
        job = _gcp.WaitJobStatus(output['job']['id'], _device.dev_id, CjtConstants.DONE, timeout=self.timeout)
      except AssertionError:
        notes = 'Job status did not transition to %s within %s seconds.' % (CjtConstants.DONE, self.timeout)
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        try:
          pages_printed = int(job['uiState']['progress'].split(':')[1])
          self.assertEqual(pages_printed, 1)
        except AssertionError:
          notes = 'Pages printed is not equal to 1.'
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        else:
          notes = 'Printed one page as expected. Status shows as printed.'
          self.LogTest(test_id, test_name, 'Passed', notes)

  def testMultiPageJobState(self):
    """Verify a multi-page print job is reported with correct state."""
    test_id = '7bbf3e1f-c972-4414-ad7c-e6054aa7416f'
    test_name = 'testMultiPageJobState'
    print 'Wait until job starts printing 7 page PDF file...'

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1.7'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error while printing 7 page PDF file.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      print 'When printer starts printing, Job State should transition to in progress.'
      try:
        _gcp.WaitJobStatus(output['job']['id'], _device.dev_id, CjtConstants.IN_PROGRESS)
      except AssertionError:
        notes = 'Job is not "In progress" while job is still printing.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        try:
          job = _gcp.WaitJobStatus(output['job']['id'], _device.dev_id, CjtConstants.DONE, timeout=self.timeout)
        except AssertionError:
          notes = 'Job status did not transition to %s within %s seconds.' % (CjtConstants.DONE, self.timeout)
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        else:
          try:
            pages_printed = int(job['uiState']['progress'].split(':')[1])
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

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1.7'], test_name, self.cjt)

    if output['success']:
      PromptAndWaitForUserAction('Press ENTER once the first page prints out.')
      delete_res = _gcp.DeleteJob(output['job']['id'])
      if delete_res['success']:
        # Since it's PDF file give the job time to finish printing.
        PromptAndWaitForUserAction('Press ENTER once printer is finished printing')
        output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG7'], test_name, self.cjt)
        try:
          self.assertTrue(output['success'])
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
        _logger.error(notes)
        self.LogTest(test_id, test_name, 'Blocked', notes)
        raise
    else:
      notes = 'Error printing multi-page PDF file.'
      _logger.error(notes)
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise

  def testJobStateEmptyInputTray(self):
    """Validate proper /control msg when input tray is empty."""
    test_id = '3e178014-b2b6-4ee0-b9b5-f2df24be10b0'
    test_name = 'testJobStateEmptyInputTray'
    print 'Empty the input tray of all paper.'

    PromptAndWaitForUserAction('Press ENTER once input tray has been emptied.')

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1.7'], test_name, self.cjt)

    if output['success']:
      try:
        job = _gcp.WaitJobStatusNotIn(output['job']['id'], _device.dev_id,
                                     [CjtConstants.QUEUED, CjtConstants.IN_PROGRESS],
                                     timeout = self.timeout)
      except AssertionError:
        notes = 'Job not found or status transitioned into Queued or In Progress within %s seconds.' % (self.timeout)
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        try:
          self.assertEqual(job['status'], CjtConstants.ERROR)
        except AssertionError:
          notes = 'Print Job is not in Error state.'
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        else:
          job_state_msg = job['uiState']['cause']
          notes = 'Job State Error msg: %s' % job_state_msg
          try:
            #TODO: Do we really want to fail here if 'tray' is not in the msg?
            self.assertIn('', job_state_msg)
          except AssertionError:
            _logger.error('The Job State error message did not contain tray')
            _logger.error(notes)
            _logger.error('Note that the error message may be ok.')
            self.LogTest(test_id, test_name, 'Failed', notes)
            raise
          else:
            PromptAndWaitForUserAction('Press ENTER after placing the papers back in the input tray.')
            print 'After placing the paper back, Job State should transition to in progress.'
            try:
              job = _gcp.WaitJobStatus(output['job']['id'], _device.dev_id, CjtConstants.IN_PROGRESS)
            except AssertionError:
              notes = 'Job is not in progress: %s' % job['status']
              _logger.error(notes)
              self.LogTest(test_id, test_name, 'Failed', notes)
              raise
            else:
              print 'Wait for the print job to finish.'
              try:
                job = _gcp.WaitJobStatus(output['job']['id'], _device.dev_id, CjtConstants.DONE, timeout=self.timeout)
              except AssertionError:
                notes = 'Job status did not transition to %s within %s seconds.' % (CjtConstants.DONE, self.timeout)
                self.LogTest(test_id, test_name, 'Failed', notes)
                raise
              else:
                notes = 'Job state: %s' % job['status']
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
    PromptAndWaitForUserAction('Press ENTER once the toner is removed.')

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1.7'], test_name, self.cjt)
    if output['success']:
      try:
        job = _gcp.WaitJobStatusNotIn(output['job']['id'], _device.dev_id,
                                     [CjtConstants.QUEUED, CjtConstants.IN_PROGRESS],
                                     timeout = self.timeout)
      except AssertionError:
        notes = 'Job not found or status transitioned into Queued or In Progress within %s seconds.' % (self.timeout)
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        try:
          self.assertEqual(job['status'], CjtConstants.ERROR)
        except AssertionError:
          notes = 'Print Job is not in Error state.'
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        else:
          job_state_msg = job['uiState']['cause']
          notes = 'Job State Error msg: %s' % job_state_msg
          try:
            # Ensure the message at least has the string or more than 4 chars.
            self.assertGreater(len(job_state_msg), 4)
          except AssertionError:
            _logger.error('The Job State error message is insufficient')
            _logger.error(notes)
            _logger.error('Note that the error message may be ok.')
            self.LogTest(test_id, test_name, 'Failed', notes)
            raise
          else:
            PromptAndWaitForUserAction('Press ENTER once the toner or ink is placed back in printer.')
            print 'After placing the toner back, Job State should transition to in progress.'
            try:
              job = _gcp.WaitJobStatus(output['job']['id'], _device.dev_id, CjtConstants.IN_PROGRESS)
            except AssertionError:
              notes = 'Job is not in progress: %s' % job['status']
              _logger.error(notes)
              self.LogTest(test_id, test_name, 'Failed', notes)
              raise
            else:
              print 'Wait for the print job to finish.'
              try:
                job = _gcp.WaitJobStatus(output['job']['id'], _device.dev_id, CjtConstants.DONE, timeout=self.timeout)
              except AssertionError:
                notes = 'Job status did not transition to %s within %s seconds.' % (CjtConstants.DONE, self.timeout)
                self.LogTest(test_id, test_name, 'Failed', notes)
                raise
              else:
                notes = 'Job state: %s' % job['status']
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

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1.7'], test_name, self.cjt)

    if output['success']:
      job_id = output['job']['id']
      print 'Wait for one page to print.'
      PromptAndWaitForUserAction('Press ENTER once network is disconnected.')

      try:
        _gcp.WaitJobStatus(job_id, _device.dev_id, CjtConstants.IN_PROGRESS, timeout=30)
      except AssertionError:
        notes = 'Job status did not transition to %s within %s seconds.' % \
                (CjtConstants.IN_PROGRESS, 30)
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        print 'Re-establish network connection to printer.'
        PromptAndWaitForUserAction('Press ENTER once network is reconnected')
        print 'Once network is reconnected, Job state should transition to in progress.'
        try:
          _gcp.WaitJobStatus(job_id, _device.dev_id, CjtConstants.IN_PROGRESS, timeout=30)
        except AssertionError:
          notes = 'Job status did not transition to %s within %s seconds.' % \
                  (CjtConstants.IN_PROGRESS, 30)
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        else:
          print 'Wait for the print job to finish.'
          try:
            job = _gcp.WaitJobStatus(output['job']['id'], _device.dev_id, CjtConstants.DONE, timeout=self.timeout)
          except AssertionError:
            notes = 'Job status did not transition to Done within %s seconds of starting print job.' % (self.timeout)
            self.LogTest(test_id, test_name, 'Failed', notes)
            raise
          else:
            notes = 'Job state: %s' % job['status']
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
    PromptAndWaitForUserAction('Press ENTER once printer reports paper jam.')

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF9'], test_name, self.cjt)

    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing %s' % Constants.IMAGES['PDF9']
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      print 'Verifying job is reported in error state.'
      try:
        _gcp.WaitJobStatus(output['job']['id'], _device.dev_id, CjtConstants.ERROR, timeout=30)
      except AssertionError:
        notes = 'Job status did not transition to %s within %s seconds.' % \
                (CjtConstants.ERROR, 30)
        _logger.error(notes)
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        print 'Now clear the print path so the printer is no longer jammed.'
        PromptAndWaitForUserAction('Press ENTER once printer is clear of jam.')
        print 'Verify print job prints after paper jam is cleared.'
        self.ManualPass(test_id, test_name)

  def testJobStateIncorrectMediaSize(self):
    """Validate proper behavior when incorrect media size is selected."""
    test_id = '0c5a757c-ab57-4383-b286-1503c09ad81f'
    test_name = 'testJobStateIncorrectMediaSize'
    print 'This test is designed to select media size that is not available.'
    print 'The printer should prompt the user to enter the requested size.'
    print 'Load input tray with letter sized paper.'

    PromptAndWaitForUserAction('Press ENTER once paper tray loaded with letter sized paper.')

    self.cjt.AddSizeOption(CjtConstants.A4_HEIGHT, CjtConstants.A4_WIDTH)

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG7'], test_name, self.cjt)

    print 'Attempting to print with A4 media size.'
    print 'Fail this test if printer does not warn user to load correct size'
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing %s' % Constants.IMAGES['PNG7']
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      PromptAndWaitForUserAction('Verify printer status, then press ENTER')
      print 'Now load printer with A4 size paper.'
      PromptAndWaitForUserAction('After placing the correct paper size, press ENTER')
      print 'Printer should continue printing and should complete the print job.'
      try:
        _gcp.WaitJobStatus(output['job']['id'], _device.dev_id, CjtConstants.DONE, timeout=self.timeout)
      except AssertionError:
        notes = 'Job status did not transition to %s within %s seconds.' % (CjtConstants.DONE, self.timeout)
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        self.ManualPass(test_id, test_name)
      
  def testMultipleJobsPrint(self):
    """Verify multiple jobs in queue are all printed."""
    test_id = '50790aa4-f276-4c12-9a06-fc0fdf446d7e'
    test_name = 'testMultipleJobsPrint'
    print 'This tests that multiple jobs in print queue are printed.'

    for _ in xrange(3):
      output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG7'], test_name, self.cjt)
      try:
        self.assertTrue(output['success'])
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
    is_off = promptForShutDown(_device.name)
    try:
      self.assertTrue(is_off)
    except AssertionError:
      notes = 'Error receiving the shutdown signal from the printer.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    for _ in xrange(3):
      print 'Submitting job#',_,' to the print queue.'
      output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG7'], test_name, self.cjt)
      try:
        self.assertTrue(output['success'])
      except AssertionError:
        notes = 'Error printing %s' % Constants.IMAGES['PNG7']
        self.LogTest(test_id, test_name, 'Blocked', notes)
        raise
      try:
        _gcp.WaitJobStatus(output['job']['id'], _device.dev_id, CjtConstants.QUEUED, timeout=30)
      except AssertionError:
        notes = 'Print job %s is not in Queued state.' %(_)
        self.LogTest(test_id, test_name, 'Blocked', notes)
        raise

    PromptUserAction('Power on the printer and wait...')
    is_added = waitForService(_device.name, True, timeout=300)
    try:
      self.assertTrue(is_added)
    except AssertionError:
      notes = 'Error receiving the power-on signal from the printer.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      # Get the new X-privet-token from the restart
      _device.GetPrivetInfo()
      print 'Verify that all 3 print jobs are printed.'
      self.ManualPass(test_id, test_name)

  def testDeleteQueuedJob(self):
    """Verify deleting a queued job is properly handled by printer."""
    test_id = '6a449854-a0d9-480b-82e0-f04342f6793a'
    test_name = 'testDeleteQueuedJob'

    is_off = promptForShutDown(_device.name)
    try:
      self.assertTrue(is_off)
    except AssertionError:
      notes = 'Error receiving the shutdown signal from the printer.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    doc_to_print = Constants.IMAGES['PNG7']

    print 'Attempting to add a job to the queue.'
    output = _gcp.Submit(_device.dev_id, doc_to_print, test_name, self.cjt)

    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing %s' % doc_to_print
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise

    try:
      _gcp.WaitJobStatus(output['job']['id'], _device.dev_id, CjtConstants.QUEUED, timeout=30)
    except AssertionError:
      notes = 'Print job is not in queued state.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise

    print 'Attempting to delete job in queued state.'
    job_delete = _gcp.DeleteJob(output['job']['id'])
    try:
      self.assertTrue(job_delete['success'])
    except AssertionError:
      notes = 'Queued job not deleted.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      PromptUserAction('Power on the printer and wait...')
      is_added = waitForService(_device.name, True, timeout=300)
      try:
        self.assertTrue(is_added)
      except AssertionError:
        notes = 'Error receiving the power-on signal from the printer.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      # Get the new X-privet-token from the restart
      _device.GetPrivetInfo()
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
    _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF5'], test_name, self.cjt)
    # Now print a valid file.
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF9'], test_name2, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Job did not print after malformatted print job.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        _gcp.WaitJobStatus(output['job']['id'], _device.dev_id, CjtConstants.DONE, timeout=self.timeout)
      except AssertionError:
        notes = 'Job status did not transition to %s within %s seconds.' % (CjtConstants.DONE, self.timeout)
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

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF10'], test_name, self.cjt)
    print 'Printing a 3 page PDF file'
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing 3 page PDF file.'
      self.LogTest(test_id, test_name, 'Blocked', notes)
      raise
    else:
      try:
        job = _gcp.WaitJobStatus(output['job']['id'], _device.dev_id, CjtConstants.DONE, timeout=self.timeout)
      except AssertionError:
        notes = 'Job status did not transition to %s within %s seconds.' % (CjtConstants.DONE, self.timeout)
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        try:
          pages_printed = int(job['uiState']['progress'].split(':')[1])
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
    LogoCert.setUpClass(cls)
    _logger.info('Sleeping for 1 day before running additional tests.')
    print 'Sleeping for 1 day before running additional tests.'
    Sleep('ONE_DAY')

  def testPrinterOnline(self):
    """validate printer has online status."""
    test_id = '5e0bf694-086a-4258-b23a-aa0d9a746dd7'
    test_name = 'testPrinterOnline'
    _device.GetDeviceDetails()
    try:
      self.assertIn('ONLINE', _device.status)
    except AssertionError:
      notes = 'Printer is not online after 24 hours.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Printer online after 24 hours.'
      self.LogTest(test_id, test_name, 'Passed', notes)


class Unregister(LogoCert):
  """Test removing device from registered status."""

  @classmethod
  def setUpClass(cls):
    LogoCert.GetDeviceDetails()

  def testUnregisterDevice(self):
    """Unregister printer."""
    test_id = 'bd9cdf91-431a-4534-a747-55ef8cbd8391'
    test_name = 'testUnregisterDevice'
    test_id2 = 'a6054736-ee47-4db4-8ad9-640ed987ac75'
    test_name2 = 'testOffDeviceIsDeleted'

    print 'Printer needs to be registered at the beginning of this testcase'
    is_registered = _device.isPrinterRegistered()
    try:
      self.assertTrue(is_registered)
    except AssertionError:
      notes = 'Printer needs to be registered before this testcase runs'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    success = _device.UnRegister(_device.auth_token)
    try:
      self.assertTrue(success)
    except AssertionError:
      notes = 'Error while deleting registered printer.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Registered printer was deleted.'
      self.LogTest(test_id, test_name, 'Passed', notes)

    print 'Wait up to 2 minutes for the printer to advertise as an unregistered device'
    success = waitForAdvertisementRegistrationStatus(_device.name, False, 120)
    try:
      self.assertTrue(success)
    except AssertionError:
      notes = 'Deleted device not found advertising or found advertising as registered'
      self.LogTest(test_id2, test_name2, 'Failed', notes)
      raise
    else:
      notes = 'Deleted device found advertising as unregistered device.'
      self.LogTest(test_id2, test_name2, 'Passed', notes)


class CloudPrinting(LogoCert):
  """Test printing using Cloud Print."""

  def setUp(self):
    # Create a fresh CJT for each test case
    self.cjt = CloudJobTicket(_device.details['gcpVersion'], _device.cdd['caps'])

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass(cls)
    LogoCert.GetDeviceDetails()

  def testPrintUrl(self):
    """Verify cloud printing simple 1 page url - google.com"""
    test_id = '9a957af4-eeed-47c3-8f12-7e60008a6f38'
    test_name = 'testPrintUrl'

    output = _gcp.Submit(_device.dev_id, Constants.GOOGLE, test_name, self.cjt, is_url=True)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing simple 1 page URL.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Google front page should print without errors.'
      print 'Fail this test if there are errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def testPrintJpg2Copies(self):
    """Verify cloud printing Jpg with copies option set to 2."""
    test_id = '734537e6-c075-4d38-bc4b-dd1b6ad1a7ca'
    test_name = 'testPrintJpg2Copies'
    if not Constants.CAPS['COPIES_CLOUD']:
      notes = 'Copies not supported.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    _logger.info('Setting copies to 2...')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddCopiesOption(2)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['JPG12'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing with copies = 2.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintPdfDuplexLongEdge(self):
    """Verify cloud printing a pdf with the duplex option set to long edge."""
    test_id = 'cb86137b-943d-47fc-adcd-663ad9f0dce8'
    test_name = 'testPrintPdfDuplexLongEdge'
    if not Constants.CAPS['DUPLEX']:
      notes = 'Duplex not supported.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    _logger.info('Setting duplex to long edge...')

    self.cjt.AddDuplexOption(CjtConstants.LONG_EDGE)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF10'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing in duplex long edge.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintPdfDuplexShortEdge(self):
    """Verify cloud printing a pdf with the duplex option set to short edge."""
    test_id = '651588ca-c4aa-4710-b203-64085834dd17'
    test_name = 'testPrintPdfDuplexShortEdge'
    if not Constants.CAPS['DUPLEX']:
      notes = 'Duplex not supported.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    _logger.info('Setting duplex to short edge...')

    self.cjt.AddDuplexOption(CjtConstants.SHORT_EDGE)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF10'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing in duplex short edge.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintColorSelect(self):
    """Verify cloud printing with color options."""
    test_id = '52686084-5ae2-4bda-b715-aba6a8972268'
    test_name = 'testPrintColorSelect'
    if not Constants.CAPS['COLOR']:
      notes = 'Color is not supported.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    _logger.info('Printing with color selected.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF13'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing color PDF with color selected.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintMediaSizeSelect(self):
    """Verify cloud printing with media size option."""
    test_id = '14ee1e62-7b38-423c-8637-50a2ae460ddc'
    test_name = 'testPrintMediaSizeSelect'
    _logger.info('Testing the selection of A4 media size.')
    PromptAndWaitForUserAction('Load printer with A4 size paper. Select return when ready.')

    self.cjt.AddSizeOption(CjtConstants.A4_HEIGHT, CjtConstants.A4_WIDTH)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG1'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error selecting A4 media size.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)
    finally:
      PromptAndWaitForUserAction('Load printer with letter size paper. Select return when ready.')

  def testPrintPdfReverseOrder(self):
    """Verify cloud printing a pdf with reverse order option."""
    test_id = '1c2610c9-4f16-42ca-9d4a-018f127c4b58'
    test_name = 'testPrintPdfReverseOrder'
    _logger.info('Print with reverse order flag set...')

    self.cjt.AddReverseOption()
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF10'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing in reverse order.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintPdfPageRangePage2(self):
    """Verify cloud printing a pdf with the page range option set to 2."""
    test_id = '4f274ec1-28f0-4201-b769-65467f7abcfd'
    test_name = 'testPrintPdfPageRangePage2'
    _logger.info('Setting page range to page 2 only')

    self.cjt.AddPageRangeOption(2, end = 2)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing with page range set to page 2 only.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintPdfPageRangePage4To6(self):
    """Verify cloud printing a pdf with the page range option set to 4-6."""
    test_id = '4f274ec1-28f0-4201-b769-65467f7abcfd'
    test_name = 'testPrintPdfPageRangePage4To6'
    _logger.info('Setting page range to 4-6...')

    self.cjt.AddPageRangeOption(4, end = 6)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing with page range set to page 4-6.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintPdfPageRangePage2And4to6(self):
    """Verify cloud printing a pdf with the page range option set to 2 and 4-6."""
    test_id = '4f274ec1-28f0-4201-b769-65467f7abcfd'
    test_name = 'testPrintPdfPageRangePage2And4to6'
    _logger.info('Setting page range to page 2 and 4-6...')

    self.cjt.AddPageRangeOption(2, end = 2)
    self.cjt.AddPageRangeOption(4, end = 6)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing with page range set to page 2 and 4-6.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgDpiSetting(self):
    """Verify cloud printing a jpg with DPI option."""
    test_id = '93c42b61-30e9-407c-bcd5-df50f418c53b'
    test_name = 'testPrintJpgDpiSetting'

    dpi_options = _device.cdd['caps']['dpi']['option']

    for dpi_option in dpi_options:
      _logger.info('Setting dpi to %s', dpi_option)

      self.cjt.AddDpiOption(dpi_option['horizontal_dpi'], dpi_option['vertical_dpi'])
      output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG8'], test_name, self.cjt)
      try:
        self.assertTrue(output['success'])
      except AssertionError:
        notes = 'Error printing with dpi set to %s' % dpi_option
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
    self.ManualPass(test_id, test_name)

  def testPrintPngFillPage(self):
    """Verify cloud printing a png with the fill page option."""
    test_id = '0f911f5f-7001-4d87-933f-c15f42823da6'
    test_name = 'testPrintPngFillPage'
    _logger.info('Setting print option to Fill Page...')

    self.cjt.AddFitToPageOption(CjtConstants.FILL)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG3'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing with Fill Page option.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintPngFitToPage(self):
    """Verify cloud printing a png with the fit to page option."""
    test_id = '5f2ab7d7-663b-4b86-b4e5-c38979baad11'
    test_name = 'testPrintPngFitToPage'
    _logger.info('Setting print option to Fit to Page...')

    self.cjt.AddFitToPageOption(CjtConstants.FIT)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG3'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing with Fit to Page option.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintPngGrowToPage(self):
    """Verify cloud printing a png with the grow to page option."""
    test_id = '09532b30-f853-458e-99bf-5c1c532573c8'
    test_name = 'testPrintPngGrowToPage'
    _logger.info('Setting print option to Grow to Page...')

    self.cjt.AddFitToPageOption(CjtConstants.GROW)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG3'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing with Grow To Page option.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintPngShrinkToPage(self):
    """Verify cloud printing a png with the shrink to page option."""
    test_id = '3309482d-d23a-4ad7-8161-8c474ab1e6de'
    test_name = 'testPrintPngShrinkToPage'
    _logger.info('Setting print option to Shrink to Page...')

    self.cjt.AddFitToPageOption(CjtConstants.SHRINK)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG3'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing with Shrink To Page option.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintPngNoFitting(self):
    """Verify cloud printing a png with the no fitting option."""
    test_id = '0c8c1bd5-7d2a-4f51-9219-36d1f6957b57'
    test_name = 'testPrintPngNoFitting'
    _logger.info('Setting print option to No Fitting...')

    self.cjt.AddFitToPageOption(CjtConstants.NO_FIT)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG3'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing with No Fitting option.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgPortrait(self):
    """Verify cloud printing a jpg with the portrait option."""
    test_id = '6e36efd8-fb5b-4fce-8d24-2cc1097a88f5'
    test_name = 'testPrintJpgPortrait'
    _logger.info('Print simple JPG file with portrait orientation.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(CjtConstants.PORTRAIT)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['JPG14'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing JPG file in portrait orientation.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgLandscape(self):
    """Verify cloud printing a jpg with the landscape option."""
    test_id = '1d97a167-bc37-4e24-adf9-7e4bdbfff553'
    test_name = 'testPrintJpgLandscape'
    _logger.info('Print simple JPG file with landscape orientation.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(CjtConstants.LANDSCAPE)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['JPG7'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing JPG file with landscape orientation.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgBlacknWhite(self):
    """Verify cloud printing a jpg with the monochrome option."""
    test_id = 'bbd3c533-fcc2-4bf1-adc9-9cd63cc35a80'
    test_name = 'testPrintJpgBlacknWhite'
    _logger.info('Print black and white JPG file.')

    self.cjt.AddColorOption(self.monochrome)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['JPG1'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing black and white JPG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgColorTestLandscape(self):
    """Verify cloud printing a jpg with the color and landscape option."""
    test_id = '26076864-6aad-44e5-96a6-4f455e751fe7'
    test_name = 'testPrintJpgColorTestLandscape'
    _logger.info('Print color test JPG file with landscape orientation.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(CjtConstants.LANDSCAPE)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['JPG2'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing color test JPG file with landscape orientation.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgPhoto(self):
    """Verify cloud printing a jpg photo with the color and landscape option."""
    test_id = '1f0e4b40-a164-4441-b3cb-182e2a5a5cdb'
    test_name = 'testPrintJpgPhoto'
    _logger.info('Print JPG photo in landscape orientation.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(CjtConstants.LANDSCAPE)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['JPG5'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing JPG photo in landscape orientation.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgSingleObject(self):
    """Verify cloud printing a single option jpg with the color and landscape option."""
    test_id = '03a22a19-8089-4150-8f1b-ceb78180713e'
    test_name = 'testPrintJpgSingleObject'
    _logger.info('Print JPG file single object in landscape.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(CjtConstants.LANDSCAPE)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['JPG7'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing single object JPG file in landscape.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgProgressive(self):
    """Verify cloud printing a progressive jpg with the color and landscape option."""
    test_id = '8ce44d03-ba45-40c5-af0f-2aacb8a6debf'
    test_name = 'testPrintJpgProgressive'
    _logger.info('Print a Progressive JPG file.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(CjtConstants.LANDSCAPE)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['JPG8'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing progressive JPEG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgMultiImageWithText(self):
    """Verify cloud printing a multi-image jpg with the color and landscape option."""
    test_id = '2d7ba1af-917b-467b-9e09-72f77cf58a56'
    test_name = 'testPrintJpgMultiImageWithText'
    _logger.info('Print multi image with text JPG file.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(CjtConstants.LANDSCAPE)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['JPG9'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing multi-image with text JPG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgMaxComplex(self):
    """Verify cloud printing a complex jpg with the color option."""
    test_id = 'c8208125-e720-406a-9308-bc80d461b08e'
    test_name = 'testPrintJpgMaxComplex'
    _logger.info('Print complex JPG file.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['JPG10'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing complex JPG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgMultiTargetPortrait(self):
    """Verify cloud printing a multi-target jpg with the color and portrait option."""
    test_id = '3ff201de-77f3-4be1-9cf2-60dc29698f0b'
    test_name = 'testPrintJpgMultiTargetPortrait'
    _logger.info('Print multi-target JPG file with portrait orientation.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(CjtConstants.PORTRAIT)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['JPG11'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing multi-target JPG file in portrait.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgStepChartLandscape(self):
    """Verify cloud printing a step-chart jpg with the color and landscape option."""
    test_id = 'f2f2cae4-e835-48e0-8632-953dd50be0ca'
    test_name = 'testPrintJpgStepChartLandscape'
    _logger.info('Print step chart JPG file in landscape orientation.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(CjtConstants.LANDSCAPE)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['JPG13'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing step chart JPG file in landscape.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgLarge(self):
    """Verify cloud printing a large jpg with the color and landscape option."""
    test_id = 'c45e7ebf-241b-4fdf-8d0b-4d7f850a2b1a'
    test_name = 'testPrintJpgLarge'
    _logger.info('Print large JPG file with landscape orientation.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(CjtConstants.LANDSCAPE)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['JPG3'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing large JPG file in landscape.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintJpgLargePhoto(self):
    """Verify cloud printing a large-photo jpg with the color and landscape option."""
    test_id = 'e30fefe9-1a32-4b22-9088-0af5fe2ffd57'
    test_name = 'testPrintJpgLargePhoto'
    _logger.info('Print large photo JPG file with landscape orientation.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(CjtConstants.LANDSCAPE)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['JPG4'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing large photo JPG file in landscape.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdf(self):
    """Test cloud printing a standard, 1 page b&w PDF file."""
    test_id = '0d4d0d33-b170-414d-a722-00e848bede10'
    test_name = 'testPrintFilePdf'
    _logger.info('Printing a black and white 1 page PDF file.')

    self.cjt.AddColorOption(self.monochrome)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF4'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing 1 page, black and white PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileColorPdf(self):
    """Test cloud printing an ICC version 4 test color PDF file."""
    test_id = 'd81fe624-c6ec-4e72-9535-9cead873a4fa'
    test_name = 'testPrintFileColorPdf'
    _logger.info('Printing a color, 1 page PDF file.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF13'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing 1 page, color PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileMultiPagePdf(self):
    """Test cloud printing a standard, 3 page color PDF file."""
    test_id = '84e4d761-594d-4930-8a91-b43d037a7422'
    test_name = 'testPrintFileMultiPagePdf'
    _logger.info('Printing a 3 page, color PDF file.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF10'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing 3 page, color PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileLargeColorPdf(self):
    """Test cloud printing a 20 page, color PDF file."""
    test_id = '005a9954-b55e-40f9-8a66-aa06b5528a78'
    test_name = 'testPrintFileLargeColorPdf'
    _logger.info('Printing a 20 page, color PDF file.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing 20 page, color PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfV1_2(self):
    """Test cloud printing PDF version 1.2 file."""
    test_id = '7cd98a62-d209-4d5a-934d-f951e0db9666'
    test_name = 'testPrintFilePdfV1_2'
    _logger.info('Printing a PDF v1.2 file.')

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1.2'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing PDF v1.2 file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfV1_3(self):
    """Test cloud printing PDF version 1.3 file."""
    test_id = 'dec3eebc-75b3-47c2-8619-0451e172cb08'
    test_name = 'testPrintFilePdfV1_3'
    _logger.info('Printing a PDF v1.3 file.')

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1.3'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing PDF v1.3 file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfV1_4(self):
    """Test cloud printing PDF version 1.4 file."""
    test_id = '881cdd22-49e8-4560-ae13-b8c79741f7d1'
    test_name = 'testPrintFilePdfV1_4'
    _logger.info('Printing a PDF v1.4 file.')

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1.4'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing PDF v1.4 file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfV1_5(self):
    """Test cloud printing PDF version 1.5 file."""
    test_id = '518c3a4b-1335-4979-b1e6-2b06acad8905'
    test_name = 'testPrintFilePdfV1_5'
    _logger.info('Printing a PDF v1.5 file.')

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1.5'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing PDF v1.5 file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfV1_6(self):
    """Test cloud printing PDF version 1.6 file."""
    test_id = '94dbee8a-e02c-4926-ad7e-a83dbff716dd'
    test_name = 'testPrintFilePdfV1_6'
    _logger.info('Printing a PDF v1.6 file.')
    return

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1.6'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing PDF v1.6 file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfV1_7(self):
    """Test cloud printing PDF version 1.7 file."""
    test_id = '2ee12493-eeaf-43cd-a136-d01227d63e9a'
    test_name = 'testPrintFilePdfV1_7'
    _logger.info('Printing a PDF v1.7 file.')

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1.7'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing PDF v1.7 file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfColorTicket(self):
    """Test cloud printing PDF file of Color Ticket in landscape orientation."""
    test_id = '4bddcf56-984b-4c4d-9c39-63459b295247'
    test_name = 'testPrintFilePdfColorTicket'
    _logger.info('Printing PDF Color ticket in with landscape orientation.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(CjtConstants.LANDSCAPE)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF2'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing color boarding ticket PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfLetterMarginTest(self):
    """Test cloud printing PDF Letter size margin test file."""
    test_id = 'a7328247-84ab-4a8f-865a-f8f30ed20fc2'
    test_name = 'testPrintFilePdfLetterMarginTest'
    _logger.info('Printing PDF Letter Margin Test.')

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF3'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing letter margin test PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfMarginTest2(self):
    """Test cloud printing PDF margin test 2 file."""
    test_id = '215a7db8-ae4b-4784-b49a-49c30cf82b53'
    test_name = 'testPrintFilePdfMarginTest2'
    _logger.info('Printing PDF Margin Test 2 file.')

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF6'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing margin test 2 PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfSimpleLandscape(self):
    """Test cloud printing PDF with landscape layout."""
    test_id = '2aaa222a-7d35-4f88-bfc0-8cf2eb5f8373'
    test_name = 'testPrintFilePdfSimpleLandscape'
    _logger.info('Printing simple PDF file in landscape.')

    self.cjt.AddPageOrientationOption(CjtConstants.LANDSCAPE)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF8'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing simple PDF file in landscape.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfCupsTestPage(self):
    """Test cloud printing PDF CUPS test page."""
    test_id = 'ae2a075b-ee7c-409c-8d2d-d08f5c2e868b'
    test_name = 'testPrintFilePdfCupsTestPage'
    _logger.info('Printing PDF CUPS test page.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF9'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing CUPS print test PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfColorTest(self):
    """Test cloud printing PDF Color Test file."""
    test_id = '882efbf9-47f2-43cd-9ee9-d4b026679406'
    test_name = 'testPrintFilePdfColorTest'
    _logger.info('Printing PDF Color Test page.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF11'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing Color Test PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfBarCodeTicket(self):
    """Test cloud printing Barcoded Ticket PDF file."""
    test_id = 'b38c0113-095e-4e73-8efe-7352852cafb7'
    test_name = 'testPrintFilePdfBarCodeTicket'
    _logger.info('Printing PDF Bar coded ticket.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF12'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing bar coded ticket PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePdfComplexTicket(self):
    """Test cloud printing complex ticket PDF file."""
    test_id = '12555398-4e1f-4305-bcc6-b2b82d665634'
    test_name = 'testPrintFilePdfComplexTicket'
    _logger.info('Printing PDF of complex ticket.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF14'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing complex ticket that is PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileSimpleGIF(self):
    """Test cloud printing simple GIF file."""
    test_id = '7c346ab2-d8b4-407b-b477-755a0432ace5'
    test_name = 'testPrintFileSimpleGIF'
    _logger.info('Printing simple GIF file.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['GIF2'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing simple GIF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileSmallGIF(self):
    """Test cloud printing a small GIF file."""
    test_id = '2e81decf-e364-4651-af1b-a516ac51f4bb'
    test_name = 'testPrintFileSmallGIF'
    _logger.info('Printing small GIF file.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['GIF4'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing small GIF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileLargeGIF(self):
    """Test cloud printing a large GIF file."""
    test_id = '72ed6bc4-1b42-4bc1-921c-4ab205dd56cd'
    test_name = 'testPrintFileLargeGIF'
    _logger.info('Printing large GIF file.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['GIF1'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing large GIF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileBlackNWhiteGIF(self):
    """Test cloud printing a black & white GIF file."""
    test_id = '7fa69496-542e-4f71-8538-7f67b907a2ec'
    test_name = 'testPrintFileBlackNWhiteGIF'
    _logger.info('Printing black and white GIF file.')

    self.cjt.AddColorOption(self.monochrome)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['GIF3'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing black and white GIF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileHTML(self):
    """Test cloud printing HTML file."""
    test_id = '46164630-7c6e-4b37-b829-5edac13888ac'
    test_name = 'testPrintFileHTML'
    _logger.info('Printing HTML file.')

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['HTML1'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing HTML file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePngA4Test(self):
    """Test cloud printing A4 Test PNG file."""
    test_id = '4c1e7474-3471-46b2-8e0d-2e605f89c129'
    test_name = 'testPrintFilePngA4Test'
    _logger.info('Printing A4 Test PNG file.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG1'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing A4 Test PNG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePngPortrait(self):
    """Test cloud printing PNG portrait file."""
    test_id = '7f1e0a95-767e-4302-8225-61d93e127a41'
    test_name = 'testPrintFilePngPortrait'
    _logger.info('Printing PNG portrait file.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG8'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing PNG portrait file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileColorPngLandscape(self):
    """Test cloud printing color PNG file."""
    test_id = '6b386438-d5cd-46c5-9b25-4ac50faf169c'
    test_name = 'testPrintFileColorPngLandscape'
    _logger.info('Printing Color PNG file in landscape.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(CjtConstants.LANDSCAPE)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG2'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing Color PNG in landscape.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileSmallPng(self):
    """Test cloud printing a small PNG file."""
    test_id = '213b84ed-6ddb-4d9b-ab27-be8d5f6d8370'
    test_name = 'testPrintFileSmallPng'
    _logger.info('Printing a small PNG file.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG3'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing small PNG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePngWithLetters(self):
    """Test cloud printing PNG containing letters."""
    test_id = '83b38406-74f2-4b2e-a74c-54998956ee18'
    test_name = 'testPrintFilePngWithLetters'
    _logger.info('Printing PNG file with letters.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(CjtConstants.LANDSCAPE)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG4'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing PNG file containing letters.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePngColorTest(self):
    """Test cloud printing PNG Color Test file."""
    test_id = '8f66270d-64df-49c7-bb49-01705b65d089'
    test_name = 'testPrintFilePngColorTest'
    _logger.info('Printing PNG Color Test file.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG5'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing Color Test PNG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePngColorImageWithText(self):
    """Test cloud printing color images with text PNG file."""
    test_id = '931f1994-eebf-4fa6-9549-f8811b4ed641'
    test_name = 'testPrintFilePngColorImageWithText'
    _logger.info('Printing color images with text PNG file.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG6'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing color images with text PNG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFilePngCupsTest(self):
    """Test cloud printing Cups Test PNG file."""
    test_id = '055898ba-25f7-4b4b-b116-ff7d499c8994'
    test_name = 'testPrintFilePngCupsTest'
    _logger.info('Printing Cups Test PNG file.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG7'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing Cups Test PNG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileLargePng(self):
    """Test cloud printing Large PNG file."""
    test_id = '852fab66-af6b-4f06-b94f-9d04508be3c6'
    test_name = 'testPrintFileLargePng'
    _logger.info('Printing large PNG file.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG9'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing large PNG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileSvgSimple(self):
    """Test cloud printing simple SVG file."""
    test_id = 'f10c0c3c-0d44-440f-8058-a0643235e2f8'
    test_name = 'testPrintFileSvgSimple'
    _logger.info('Printing simple SVG file.')

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['SVG2'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing simple SVG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileSvgWithImages(self):
    """Test cloud printing SVG file with images."""
    test_id = '613e3f50-365f-4d4e-be72-d04202f74de4'
    test_name = 'testPrintFileSvgWithImages'
    _logger.info('Printing SVG file with images.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['SVG1'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing SVG file with images.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileTiffRegLink(self):
    """Test cloud printing TIFF file of GCP registration link."""
    test_id = 'ff85ffb1-7032-4006-948d-1725d93c5c5a'
    test_name = 'testPrintFileTiffRegLink'
    _logger.info('Printing TIFF file of GCP registration link.')

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['TIFF1'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing TIFF file of GCP registration link.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)

  def testPrintFileTiffPhoto(self):
    """Test cloud printing TIFF file of photo."""
    test_id = '983ba7b4-ced0-4144-81cc-6abe89e63f78'
    test_name = 'testPrintFileTiffPhoto'
    _logger.info('Printing TIFF file of photo.')

    self.cjt.AddColorOption(self.color)
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['TIFF2'], test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing TIFF file of photo.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.ManualPass(test_id, test_name)


if __name__ == '__main__':
  runner = unittest.TextTestRunner(verbosity=2)
  suite = unittest.TestSuite()

  for testsuite in Constants.TEST['RUN']:
    if testsuite.startswith('#'):
      continue
    print 'Adding %s to list of suites to run' % (testsuite)
    suite.addTest(unittest.makeSuite(globals()[testsuite]))

  runner.run(suite)
