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

import _log
import _sheets


import optparse
import os
import platform
import re
import sys
import time
import traceback
import unittest

from _common import Sleep
from _common import BlueText
from _common import GreenText
from _common import RedText
from _common import PromptAndWaitForUserAction
from _common import PromptUserAction
from _config import Constants
from _cpslib import GCPService
from _device import Device
from _oauth2 import Oauth2
from _ticket import CloudJobTicket, GCPConstants
from _transport import Transport
from _zconf import MDNS_Browser
from _zconf import Wait_for_privet_mdns_service


# Module level variables
_logger = None
_transport = None
_device = None
_oauth2 = None
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
  global _device
  global _gcp
  global _logger
  global _oauth2
  global _transport

  # Initialize globals and constants
  options, unused_args = _ParseArgs()
  _logger = _log.GetLogger('LogoCert', logdir=options.logdir,
                          loglevel=options.debug, stdout=options.stdout)
  _oauth2 = Oauth2(_logger)
  # Retrieve access + refresh tokens
  _oauth2.GetTokens()

  # Wait to receive Privet printer advertisements. Timeout in 30 seconds
  printer_service = Wait_for_privet_mdns_service(30, Constants.PRINTER['NAME'],
                                                 _logger)

  if printer_service is None:
    _logger.info("No printers discovered under "+ options.printer)
    sys.exit()

  privet_port = None

  if hasattr(printer_service, 'port'):
    privet_port = int(printer_service.port)
    _logger.debug('Privet advertises port: %d', privet_port)

  _gcp = GCPService(Constants.AUTH["ACCESS"])
  _device = Device(_logger, Constants.AUTH["ACCESS"], _gcp,
                   privet_port= privet_port if 'PORT' not in Constants.PRINTER
                   else Constants.PRINTER['PORT'])
  _transport = Transport(_logger)

  if Constants.TEST['SPREADSHEET']:
    global _sheet
    _sheet = _sheets.SheetMgr(_logger, _oauth2.storage.get(), Constants)
  # pylint: enable=global-variable-undefined


def LogTestSuite(name):
  """Log a test result.

  Args:
    name: string, name of the testsuite that is logging.
  """
  print ('========================================'
         '========================================')
  print '                     Starting %s testSuite'% (name)
  print ('========================================'
         '========================================')
  if Constants.TEST['SPREADSHEET']:
    row = [name,'','','','','','','']
    _sheet.AddRow(row)


def isPrinterAdvertisingAsRegistered(service):
  """Checks the printer's privet advertisements and see if it is advertising
     as registered or not

      Args:
        service: ServiceInfo, printer's service Info
      Returns:
        boolean, True = advertising as registered,
                 False = advertising as unregistered,
                 None = advertisement not found
      """

  return (service.properties['id'] and
          'online' in service.properties['cs'].lower())


def waitForAdvertisementRegStatus(name, is_wait_for_reg, timeout):
  """Wait for the device to privet advertise as registered or unregistered

      Args:
        name: string, device status to wait on
        is_wait_for_reg: boolean, True for registered , False for unregistered
        timeout: integer, seconds to wait for the service update
      Returns:
        boolean, True = status observed, False = status not observed.
      """
  global _logger

  end = time.time() + timeout
  while time.time() < end:
    service = Wait_for_privet_mdns_service(end-time.time(), name, _logger)
    if service is None:
      _logger.info("No printers discovered under " + name)
    else:
      is_registered = isPrinterAdvertisingAsRegistered(service)
      if is_registered is is_wait_for_reg:
        return True
  return False


def writeRasterToFile(file_path, content):
  """ Save a raster image to file

        Args:
          file_path: string, file path to write to
          content: string, content to write
        """
  f = open(file_path, 'wb')
  f.write(content)
  f.close()
  print "Wrote Raster file:%s to disk" % file_path


def getRasterImageFromCloud(pwg_path, img_path):
  """ Submit a GCP print job so that the image is coverted to a supported raster
      file that can be downloaded. Then download the raster image from the cloud
      and save it to disk

      Args:
        pwg_path: string, destination file path of the pwg_raster image
        img_path: string, src file path of the image to convert from
      """

  #
  cjt = CloudJobTicket(_device.details['gcpVersion'])
  if Constants.CAPS['COLOR']:
    cjt.AddColorOption(GCPConstants.COLOR)

  print 'Generating pwg-raster via cloud print'
  output = _gcp.Submit(_device.dev_id, img_path,
                       'LocalPrinting Raster Setup', cjt)
  if not output['success']:
    print 'ERROR: Cloud printing failed.'
    raise
  else:
    try:
      _gcp.WaitJobStateIn(output['job']['id'], _device.dev_id,
                          GCPConstants.IN_PROGRESS)
    except AssertionError:
      print 'GCP ERROR: Job not observed to be in progress.'
      raise
    else:
      try:
        res = _gcp.FetchRaster(output['job']['id'])
      except AssertionError:
        print "ERROR: FetchRaster() failed."
        print "LocalPrinting suite cannot run without raster files."
        raise
      else:
        writeRasterToFile(pwg_path, res)
        print '[Configurable timeout] PRINTING'
        _gcp.WaitJobStateIn(output['job']['id'], _device.dev_id,
                           GCPConstants.DONE,
                            timeout=Constants.TIMEOUT['PRINTING'])




def getLocalPrintingRasterImages():
  """ Checks to see if the raster images used for local printing exist on the
      machine, generate and store to disk if not
      """
  if not os.path.exists(Constants.IMAGES['PWG1']):
    print '\n%s not found.'% (Constants.IMAGES['PWG1'])
    print 'Likely that this is the first time LocalPrinting suite is run.'
    getRasterImageFromCloud(Constants.IMAGES['PWG1'], Constants.IMAGES['PNG7'])

  if not os.path.exists(Constants.IMAGES['PWG2']):
    print '\n%s not found.' % (Constants.IMAGES['PWG2'])
    print 'Likely that this is the first time LocalPrinting suite is run.'
    getRasterImageFromCloud(Constants.IMAGES['PWG2'], Constants.IMAGES['PDF10'])


class LogoCert(unittest.TestCase):
  """Base Class to drive Logo Certification tests."""

  def shortDescription(self):
    '''Overriding the docstring printout function'''
    doc = self._testMethodDoc
    msg =  doc and doc.split("\n")[0].strip() or None
    return BlueText('\n=================================='
                    '====================================\n' + msg + '\n')


  @classmethod
  def setUpClass(cls, suite=None):
    options, unused_args = _ParseArgs()
    cls.loadtime = options.loadtime
    cls.username = options.email
    cls.autorun = options.autorun
    cls.printer = options.printer

    cls.monochrome = GCPConstants.MONOCHROME
    cls.color = (GCPConstants.COLOR if Constants.CAPS['COLOR']
                 else cls.monochrome)
    # Refresh access token in case it has expired
    _oauth2.RefreshToken()
    _device.auth_token = Constants.AUTH['ACCESS']
    _gcp.auth_token = Constants.AUTH['ACCESS']

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
    result = ''
    while result.lower() not in ['y','n']:
      result = PromptAndWaitForUserAction('Enter "y" or "n"')
    try:
      self.assertEqual(result.lower(), 'y')
    except AssertionError:
      notes = PromptAndWaitForUserAction('Type in additional notes for test '
                                         'failure, hit return when finished')
      self.LogTest(test_id, test_name, 'Failed', notes)
      return False
    else:
      self.LogTest(test_id, test_name, 'Passed')
      return True


  def LogTest(self, test_id, test_name, result, notes=''):
    """Log a test result.

    Args:
      test_id: integer, test id in the TestTracker application.
      test_name: string, name of the test.
      result: string, ["Passed", "Failed", "Skipped", "Not Run"]
      notes: string, notes to include with the test result.
    """
    failure = False if result.lower() in ['passed','skipped','n/a'] else True

    console_result = RedText(result) if failure else GreenText(result)
    console_test_name = RedText(test_name) if failure else GreenText(test_name)

    print '' # For spacing
    _logger.info('Test ID: %s', test_id)
    _logger.info('Result: %s', console_result)
    _logger.info('Name: %s', console_test_name)

    if notes:
      console_notes = RedText(notes) if failure else GreenText(notes)
      _logger.info('Notes: %s', console_notes)

    if Constants.TEST['SPREADSHEET']:
      row = [str(test_id), test_name, result, notes,'','','']
      if failure:
        # If failed, generate the cmd that to rerun this testcase
        # Get module name - name of this python script
        module = 'testcert'
        # Get the caller's class name
        testsuite = sys._getframe(1).f_locals['self'].__class__.__name__
        # Since some testcases contain multiple test ids, we cannot simply use
        # test_name to invoke the testcase it belongs to
        # Use traceback to get a list of functions in the callstack that begins
        # with test, the current testcase is the last entry on the list
        pattern = r', in (test.+)\s'
        testcase = [re.search(pattern, x).group(1) for x in
                    traceback.format_stack() if
                    re.search(pattern, x) is not None][-1]
        row.append('python -m unittest %s.%s.%s' %(module,testsuite,testcase))
      _sheet.AddRow(row)


  @classmethod
  def GetDeviceDetails(cls):
    _device.GetDeviceDetails()
    if not _device.name:
      _logger.error('Error finding device via privet.')
      _logger.error('Check printer model in _config file.')
      raise unittest.SkipTest('Could not find device via privet.')
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
    """Record test environment details to Google Sheets."""
    test_id = '459f04a4-7109-404c-b9e3-64573a077a65'
    test_name = 'testEnvironment'

    os_type = '%s %s' % (platform.system(), platform.release())
    python_version = sys.version

    notes = 'OS: %s\n' % os_type
    notes += 'Python: %s\n' % python_version
    self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterDetails(self):
    """Record printer details to Google Sheets."""
    test_id = 'ec2f8266-6c3e-4ebd-a7b5-df4792a5d93a'
    test_name = 'testPrinterDetails'

    notes = 'Manufacturer: %s\n' % Constants.PRINTER['MANUFACTURER']
    notes += 'Model: %s\n' % Constants.PRINTER['MODEL']
    notes += 'Name: %s\n' % Constants.PRINTER['NAME']
    notes += 'Device Status: %s\n' % Constants.PRINTER['STATUS']
    notes += 'Firmware: %s\n' % Constants.PRINTER['FIRMWARE']
    notes += 'Serial Number: %s\n' % Constants.PRINTER['SERIAL']
    notes += self.getCAPS()
    self.LogTest(test_id, test_name, 'Passed', notes)

  def getCAPS(self):
    caps = 'CAPS = {\n'
    for k,v in Constants.CAPS.iteritems():
      caps += "  '%s': %s,\n" % (k,v)
    caps += '}\n'
    return caps


class Privet(LogoCert):
  """Verify device integrates correctly with the Privet protocol.

  These tests should be run before a device is registered.
  """
  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass(cls)
    _device.assertPrinterIsUnregistered()


  def testPrivetInfoAPI(self):
    """Verify device responds to PrivetInfo API requests."""
    test_id = '7201b68f-de0b-4e93-a1a6-d674af9ec6ec'
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
    test_id = '58fedd52-3bc4-472b-897e-55ee5675fa5c'
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
    test_id = 'a0421845-9477-487f-8674-4203cbe6801b'
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
    test_id = '4c055e06-02aa-436d-b700-80f184e84f47'
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
    test_id = 'd469199f-fcbd-4a83-90bf-772453be2b09'
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
    test_id = '7a5c02f3-26f6-4df4-b8c8-953bedd4ba2d'
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
    test_id = 'c3ea4263-3745-4d69-8dd4-578f5e5a336b'
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
    test_id = '8ab9ac16-0c6e-47ec-a24e-c5ad4f77abb2'
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
    test_id = 'ffa0d9dc-840f-486a-a890-91773fc2b12d'
    test_name = 'testPrivetAccessTokenAPI'
    api = 'accesstoken'
    if Constants.CAPS['LOCAL_PRINT']:
      expected_return_code = 200
    else:
      expected_return_code = 404
    response = _transport.HTTPGet(_device.privet_url[api],
                                  headers=_device.headers)
    try:
      self.assertIsNotNone(response)
    except AssertionError:
      notes = 'No response received from %s' % _device.privet_url[api]
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertEqual(response.status_code, expected_return_code)
      except AssertionError:
        notes = ('Incorrect return code from %s: Got %d, Expected %d.\n'
                 % (_device.privet_url[api], response.status_code,
                    expected_return_code))
        notes += 'Please confirm LOCAL_PRINT is set correctly in _config.py\n'
        if response.status_code == 404:
          notes += 'Could also be fine since /privet/accesstoken is optional'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = '%s returned response code %d' % (_device.privet_url[api],
                                                  response.status_code)
        self.LogTest(test_id, test_name, 'Passed', notes)


  def testPrivetCapsAPI(self):
    """Verify unregistered device Privet Capabilities API returns correct rc."""
    test_id = '3bd87d10-301d-43b4-b959-96ede9537526'
    test_name = 'testPrivetCapsAPI'
    api = 'capabilities'
    if Constants.CAPS['LOCAL_PRINT']:
      expected_return_code = 200
    else:
      expected_return_code = 404
    response = _transport.HTTPGet(_device.privet_url[api],
                                  headers=_device.headers)
    try:
      self.assertIsNotNone(response)
    except AssertionError:
      notes = 'No response received from %s' % _device.privet_url[api]
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertEqual(response.status_code, expected_return_code)
      except AssertionError:
        notes = ('Incorrect return code from %s: Got %d, Expected %d.\n'
                 % (_device.privet_url[api], response.status_code,
                    expected_return_code))
        notes += 'Please confirm LOCAL_PRINT is set correctly in _config.py\n'
        if response.status_code == 404:
          notes += 'Could also be fine since /privet/capabilities is optional'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = '%s returned code %d' % (_device.privet_url[api],
                                         response.status_code)
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetPrinterAPI(self):
    """Verify unregistered device Privet Printer API returns correct rc."""
    test_id = 'c957966b-b63c-4827-94fa-1bf1fe930638'
    test_name = 'testPrivetPrinterAPI'
    api = 'printer'
    expected_return_codes = [200, 404]
    response = _transport.HTTPGet(_device.privet_url[api],
                                  headers=_device.headers)
    try:
      self.assertIsNotNone(response)
    except AssertionError:
      notes = 'No response received from %s' % _device.privet_url[api]
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertIn(response.status_code, expected_return_codes)
      except AssertionError:
        notes = 'Incorrect return code, found %d' % response.status_code
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = '%s returned code %d' % (_device.privet_url[api],
                                         response.status_code)
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetUnknownURL(self):
    """Verify device returns 404 return code for unknown url requests."""
    test_id = '12119bbe-7707-44f3-8743-8cde0696dcd0'
    test_name = 'testPrivetUnknownURL'
    response = _transport.HTTPGet(_device.privet_url['INVALID'],
                                 headers=_device.headers)
    try:
      self.assertIsNotNone(response)
    except AssertionError:
      notes = 'No response code received.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertEqual(response.status_code, 404)
      except AssertionError:
        notes = 'Wrong return code received. Received %d' % response.status_code
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Received correct return code: %d' % response.status_code
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetRegisterAPI(self):
    """Verify unregistered device exposes register API."""
    test_id = 'f875316e-7189-4321-8ac7-bf5e1bd53d8d'
    test_name = 'testPrivetRegisterAPI'

    success = _device.StartPrivetRegister()
    try:
      self.assertTrue(success)
    except AssertionError:
      notes = 'Error starting privet registration.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Privet registration API working correctly'
      self.LogTest(test_id, test_name, 'Passed', notes)
      # Cancel the registration so the printer is not in an unknown state
      _device.CancelRegistration()

  def testPrivetRegistrationInvalidParam(self):
    """Verify device return error if invalid registration param given."""
    test_id = 'b2d25268-86aa-41f5-8891-3a5e29c4dbff'
    test_name = 'testPrivetRegistrationInvalidParam'

    url = _device.privet_url['register']['invalid']
    params = {'user': Constants.USER['EMAIL']}
    response = _transport.HTTPPost(url, headers=_device.headers, params=params)
    try:
      self.assertIsNotNone(response)
    except AssertionError:
      notes = 'No response received.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertEqual(response.status_code, 200)
      except AssertionError:
        notes = 'Response code from invalid registration params: %d' % (
            response.status_code)
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        info = response.json()
        try:
          self.assertIn('error', info)
        except AssertionError:
          notes = 'Did not find error message. Error message: %s' % (
            info)
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        else:
          notes = 'Received correct error code and response: %d\n%s' % (
            response.status_code, info)
          self.LogTest(test_id, test_name, 'Passed', notes)
        finally:
          _device.CancelRegistration()

  def testPrivetInfoAPIEmptyToken(self):
    """Verify device returns code 200 if Privet Token is empty."""
    test_id = '1c3d8852-0130-49e1-baab-396fabb774a9'
    test_name = 'testPrivetInfoAPIEmptyToken'
    response = _transport.HTTPGet(_device.privet_url['info'],
                                 headers=_device.privet.headers_empty)
    try:
      self.assertIsNotNone(response)
    except AssertionError:
      notes = 'No response code received.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertEqual(response.status_code, 200)
      except AssertionError:
        notes = 'Return code received: %d' % response.status_code
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Return code: %d' % response.status_code
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoAPIInvalidToken(self):
    """Verify device returns code 200 if Privet Token is invalid."""
    test_id = '83eafa05-bfe4-480a-8a24-c44e57b78252'
    test_name = 'testPrivetInfoAPIInvalidToken'
    response = _transport.HTTPGet(_device.privet_url['info'],
                                 headers=_device.privet.headers_invalid)
    try:
      self.assertIsNotNone(response)
    except AssertionError:
      notes = 'No response code received.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertEqual(response.status_code, 200)
      except AssertionError:
        notes = 'Return code received: %d' % response.status_code
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Return code: %d' % response.status_code
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrivetInfoAPIMissingToken(self):
    """Verify device returns code 400 if Privet Token is missing."""
    test_id = 'bdd2be1d-1ee1-4348-b95d-59916947e10b'
    test_name = 'testPrivetInfoAPIMissingToken'
    response = _transport.HTTPGet(_device.privet_url['info'],
                                 headers=_device.privet.headers_missing)
    try:
      self.assertIsNotNone(response)
    except AssertionError:
      notes = 'No response code received.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        self.assertEqual(response.status_code, 400)
      except AssertionError:
        notes = 'Return code received: %d' % response.status_code
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Return code: %d' % response.status_code
        self.LogTest(test_id, test_name, 'Passed', notes)

  def testDeviceRegistrationInvalidClaimToken(self):
    """Verify a device will not register if the claim token is invalid."""
    test_id = '80afa1d1-bd62-4534-87e6-49f9905f6973'
    test_name = 'testDeviceRegistrationInvalidClaimToken'
    try:
      self.assertTrue(_device.StartPrivetRegister())
    except AssertionError:
      notes = 'Error starting privet registration.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        PromptUserAction('ACCEPT the registration request on the Printer UI '
                         'and wait...')
        try:
          self.assertTrue(_device.GetPrivetClaimToken())
        except AssertionError:
          notes = 'Error getting claim token.'
          self.LogTest(test_id, test_name, 'Failed', notes)
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
    test_id = 'ac798d92-4789-4e0e-ad59-da5ce5ae0be2'
    test_name = 'testDeviceRegistrationInvalidUserAuthToken'
    try:
      self.assertTrue(_device.StartPrivetRegister())
    except AssertionError:
      notes = 'Error starting privet registration.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        PromptUserAction('ACCEPT the registration request on the Printer UI '
                         'and wait...')
        print 'Note: some printers may not show a registration request.'
        try:
          self.assertTrue(_device.GetPrivetClaimToken())
        except AssertionError:
          notes = 'Error getting claim token.'
          self.LogTest(test_id, test_name, 'Failed', notes)
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
    test_id = '56f55e15-a170-4963-8523-eedd69877892'
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
      self.assertIn(Constants.PRINTER['NAME'], _device.name)
    except AssertionError:
      notes = 'NAME in _config.py does not match. Found %s' % _device.name
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
      self.assertIn(Constants.PRINTER['NAME'], _device.cdd['name'])
    except AssertionError:
      notes = ('NAME in _config.py does not match name in  CDD. Found %s in CDD'
               % _device.cdd['name'])
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Printer name: %s' % _device.name
      self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterStatus(self):
    """Verify printer has online status."""
    test_id = '0197ce66-ab79-4b0c-be02-c78325cda7fe'
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
    test_id = '5be33583-4acb-4e6f-9c28-cbf4070839bd'
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
      notes = 'Model incorrect, printer details: %s' % _device.details['model']
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
    test_id = '2df537db-2de1-433e-94e0-cf87782d76db'
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
          _device.details['manufacturer'])
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

  def testPrinterUUID(self):
    """Verify printer provides a UUID ( equilvalent to serial number )."""
    test_id = '777cb00b-7297-4268-8d76-b96ef98df30f'
    test_name = 'testPrinterUUID'
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
    test_id = '36d37e66-5aac-446a-bcaf-3815dc2169da'
    test_name = 'testPrinterGCPVersion'
    try:
      self.assertIn('gcpVersion', _device.details)
    except AssertionError:
      notes = 'GCP Version not found in printer details.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    try:
      self.assertEqual('2.0', _device.details['gcpVersion'])
    except AssertionError:
      notes = 'Version 2.0 not found in GCP Version support. Found %s' % (
          _device.details['gcpVersion'])
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
    test_id = '139b03d7-117b-4e20-ba7d-6a3968d03804'
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
    test_id = '2e2e0414-2775-4a41-be17-5698c14f85b6'
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
          _device.details['type'])
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
    test_id = 'dbc975aa-6005-4b00-9ead-c9ce42f387f2'
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
    test_id = '5740c76a-7d69-4304-a5f4-e263fb98a5ce'
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
    test_id = '7811e41d-90ea-44c5-b522-ea45751ef6a0'
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
    test_id = '6503a6b0-5e69-4165-ae7a-27d080f995f0'
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
    test_id = 'd5668a87-4341-4891-9f07-7da377ce4eea'
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
    test_id = 'e46a6823-0a94-4b9a-a7fd-afab3b9e5c73'
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
    test_id = '6d06cc18-6b4a-489a-bdfb-cccd7c3ee0d8'
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
    test_id = '6c0d4832-7ca5-4ab6-a483-997f2cea26f0'
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
    test_id = '87762b98-7bbf-4edd-92e8-b5495b7fc8e3'
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
    test_id = 'eb19cc7e-556f-4356-a3b9-c2d5979fa4ca'
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
    test_id = '3998c0b2-1277-4e60-b7ff-7ac28c5d8aba'
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
    test_id = '438bb772-119f-42e5-a624-d0a543edba95'
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
    test_id = '6932133f-b2b4-420e-a95e-5d5ec2a70d8e'
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
    test_id = '17145e5e-8bea-46cc-b9bc-c8e0c396756b'
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
    test_id = '2835bd83-2009-4864-82e4-33ae7e424557'
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
    test_id = '75fbbffe-5530-4523-a4b8-4dfd0b9aee08'
    test_name = 'testCapsDuplex'
    if not Constants.CAPS['DUPLEX']:
      if 'duplex' in _device.cdd['caps']:
        notes = 'Error in _config file, DUPLEX should be True'
        self.LogTest(test_id, test_name, 'Failed', notes)
      else:
        self.LogTest(test_id, test_name, 'Skipped', 'Duplex not supported')
      return
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
    test_id = '2c87558d-d6a5-4f36-b10c-8e77aad2b53a'
    test_name = 'testCapsCopies'
    if not Constants.CAPS['COPIES_CLOUD']:
      if 'copies' in _device.cdd['caps']:
        notes = 'Error in _config file, COPIES_CLOUD should be True'
        self.LogTest(test_id, test_name, 'Failed', notes)
      else:
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
    test_id = '40cb422c-f1e6-49ea-936a-62c9bb667f13'
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
    test_id = '69c8f693-ad42-4a77-b239-4f40205fca85'
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
    test_id = '4f398f26-9770-49f0-9e34-523bd41d8f1c'
    test_name = 'testCapsCollate'
    if not Constants.CAPS['COLLATE']:
      if 'collate' in _device.cdd['caps']:
        notes = 'Error in _config file, COLLATE should be True'
        self.LogTest(test_id, test_name, 'Failed', notes)
      else:
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
    test_id = '317fcdca-e663-41f9-b48a-8779dfe2f1ad'
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
    test_id = '7d60c7c7-08ed-45f2-9e39-1a50d45467a6'
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
    test_id = 'c29ae530-3395-4136-9289-47e93e9975da'
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
    test_id = '52873b94-ef48-4601-975e-4d90f2a85d51'
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
    test_id = '4004adbd-9322-402b-8e63-942b710cbaad'
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
    test_id = 'a9cbdeb3-c8a8-405c-a317-940a0b761f55'
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
    test_id = '5ad8b344-4326-4456-a874-054b56bf68cc'
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
    test_id = 'f461801f-bc2e-416c-8949-d6d9971f05b1'
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
    _device.assertPrinterIsUnregistered()


  def testDeviceAdvertisePrivet(self):
    """Verify printer under test advertises itself using Privet."""
    test_id = '5a24949f-1c78-4a7d-8f52-4f4c57b78f76'
    test_name = 'testDeviceAdvertisePrivet'

    print 'Listening for the printer\'s advertisements for up to 60 seconds'
    service = Wait_for_privet_mdns_service(60, Constants.PRINTER['NAME'],
                                           _logger)
    try:
      self.assertIsNotNone(service)
    except AssertionError:
      notes = 'Device is not found advertising in privet'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      is_registered = isPrinterAdvertisingAsRegistered(service)
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
    test_id = 'e8528e4d-370b-43a3-aee2-ad6f048dc367'
    test_name = 'testDeviceSleepingAdvertisePrivet'

    print 'Put the printer in sleep mode.'
    PromptAndWaitForUserAction('Press ENTER when printer is sleeping.')

    print 'Listening for the printer\'s advertisements for up to 60 seconds'
    service = Wait_for_privet_mdns_service(60, Constants.PRINTER['NAME'],
                                           _logger)
    try:
      self.assertIsNotNone(service)
    except AssertionError:
      notes = 'Device is not found advertising in privet'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      is_registered = isPrinterAdvertisingAsRegistered(service)
      try:
        self.assertFalse(is_registered)
      except AssertionError:
        notes = 'Device not advertising as a registered device in sleep mode'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Device is advertising as an unregistered device in sleep mode'
        self.LogTest(test_id, test_name, 'Passed', notes)


  def testDeviceOffNoAdvertisePrivet(self):
    """Verify powered off device does not advertise using Privet."""
    test_id = '27fba22f-e8b1-4fe2-821f-fff5ef4cac27'
    test_name = 'testDeviceOffNoAdvertisePrivet'

    PromptAndWaitForUserAction('Press ENTER once printer is powered off')

    print 'Listening for the printer\'s advertisements for up to 60 seconds'
    service = Wait_for_privet_mdns_service(60, Constants.PRINTER['NAME'],
                                           _logger)
    try:
      self.assertIsNone(service)
    except AssertionError:
      notes = 'Device found advertising when powered off'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Device no longer advertising when powered off'
      self.LogTest(test_id, test_name, 'Passed', notes)

      """Verify freshly powered on device advertises itself using Privet."""
      test_id2 = '6f87d61b-8784-41be-bb38-0405f85cb2e3'
      test_name2 = 'testDeviceOffPowerOnAdvertisePrivet'

      PromptUserAction('Power on the printer and wait...')
      service = Wait_for_privet_mdns_service(300, Constants.PRINTER['NAME'],
                                             _logger)
      try:
        self.assertIsNotNone(service)
      except AssertionError:
        notes = 'Device is not advertising in privet when freshly powered on'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        is_registered = isPrinterAdvertisingAsRegistered(service)
        try:
          self.assertFalse(is_registered)
        except AssertionError:
          notes = 'Device advertised as registered when freshly powered on'
          self.LogTest(test_id2, test_name2, 'Failed', notes)
          raise
        else:
          notes = 'Device advertised as unregistered when freshly powered on'
          self.LogTest(test_id2, test_name2, 'Passed', notes)
        finally:
          # Get the new X-privet-token from the restart
          _device.GetPrivetInfo()

  def testDeviceRegistrationNotLoggedIn(self):
    """Test printer cannot be registered if user not logged in."""
    test_id = '619926b7-c051-4d67-81b4-bb68bb4812a8'
    test_name = 'testDeviceRegistrationNotLoggedIn'

    success = _device.Register('ACCEPT the registration request on Printer UI '
                               'and wait...', use_token=False)
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


  def testDeviceCancelRegistrationPanelUI(self):
    """Test printer cancellation prevents registration."""
    test_id = '842259b0-13df-496c-81bf-1f06bdd3a35f'
    test_name = 'testDeviceCancelRegistrationPanelUI'
    _logger.info('Testing printer registration cancellation.')

    if not Constants.CAPS['PRINTER_PANEL_UI']:
      notes = 'No Printer Panel UI registration support.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return

    print 'Testing printer registration cancellation.'
    print 'Do not accept printer registration request on Printer Panel UI.'

    registration_success = _device.Register('CANCEL the registration request on'
                                            ' Printer Panel UI and wait...')
    if not registration_success:
      # Confirm the user's account has no registered printers
      res = _gcp.Search(_device.name)
      try:
        # Assert that 'printers' list is empty
        self.assertFalse(res['printers'])
      except AssertionError:
        notes = 'Unable to cancel registration request from Printer Panel UI.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        PromptAndWaitForUserAction('Make sure printer is unregistered before '
                                   'proceeding. Press ENTER to continue')
        raise
      else:
        notes = 'Cancelled registration attempt from Printer Panel UI.'
        self.LogTest(test_id, test_name, 'Passed', notes)
    else:
      notes = 'Error cancelling registration process.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      _device.CancelRegistration()

  def testDeviceCancelRegistrationWebUI(self):
    """Test printer cancellation prevents registration."""
    test_id = '29194599-2629-44a0-b3c9-c5e54c5cec80'
    test_name = 'testDeviceCancelRegistrationWebUI'
    _logger.info('Testing printer registration cancellation from printer web UI.')

    if not Constants.CAPS['WEB_URL_UI']:
      notes = 'No Printer Web UI registration support.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return

    print 'Testing printer registration cancellation.'
    print 'Do not accept printer registration request on Printer Web UI.'

    registration_success = _device.Register('CANCEL the registration request on'
                                            ' Printer Web UI and wait...')
    if not registration_success:
      # Confirm the user's account has no registered printers
      res = _gcp.Search(_device.name)
      try:
        # Assert that 'printers' list is empty
        self.assertFalse(res['printers'])
      except AssertionError:
        notes = 'Unable to cancel registration request.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        PromptAndWaitForUserAction('Make sure printer is unregistered before '
                                   'proceeding. Press ENTER to continue')
        raise
      else:
        notes = 'Cancelled registration attempt from Printer Web UI.'
        self.LogTest(test_id, test_name, 'Passed', notes)
    else:
      notes = 'Error cancelling registration process.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      _device.CancelRegistration()

class Registration(LogoCert):
  """Test device registration."""

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass(cls)
    _device.assertPrinterIsUnregistered()

  def test_01_DeviceRegistrationTimeOut(self):
    """Verify printer registration times out properly"""
    test_id = '1ce516e7-f831-465c-9ceb-2af9050b0dd9'
    test_name = 'testDeviceRegistrationNoAccept'

    if not (Constants.CAPS['PRINTER_PANEL_UI'] or Constants.CAPS['WEB_URL_UI']):
      notes = 'Printer automatically accepts registration requests.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return

    ui_str = 'printer panel' if Constants.CAPS['PRINTER_PANEL_UI'] else 'web'
    print 'Do not select accept/cancel registration from the %s U/I.' % ui_str
    print 'Wait for the registration request to time out.'

    # Timeout test
    success = _device.StartPrivetRegister()
    if success:
      PromptAndWaitForUserAction('Press ENTER once the printer registration '
                                 'times out.')
      # Confirm the user's account has no registered printers
      res = _gcp.Search(_device.name)
      try:
        self.assertFalse(res['printers'])
      except AssertionError:
        notes = ('Not able to cancel printer registration from '
                 'printer UI timeout.')
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = 'Printer registration cancelled from printer UI timeout.'
        self.LogTest(test_id, test_name, 'Passed', notes)
    else:
      notes = 'Not able to initiate printer registration.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

  def test_02_DeviceRegistrationPanelUI(self):
    """Verify printer panel UI shows registration prompt"""
    test_id = 'dd233ea2-42e2-4a1e-a9ff-4df727edd591'
    test_name = 'testDeviceAcceptRegistrationPrinterPanelUI'

    if not Constants.CAPS['PRINTER_PANEL_UI']:
      notes = 'No printer panel UI registration support.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return

    # Verify printer must accept registration requests on the printer panel
    print 'Validate that the printer panel UI correctly showed a GCP '
    print 'registration request during the previous "timeout" test'
    print 'If printer does not have accept/cancel on printer panel,'
    print 'Fail this test.'
    self.ManualPass(test_id, test_name, print_test=False)

  def test_03_DeviceRegistrationWebUI(self):
    """Verify Web URL UI shows registration prompt"""
    test_id = 'e6a0cd4a-6db6-441d-9733-c7fb8e163ddc'
    test_name = 'testDeviceAcceptRegistrationWebURLUI'

    if not Constants.CAPS['WEB_URL_UI']:
      notes = 'No Printer Web UI registration support.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return

    # Verify printer must accept registration requests on the printer panel
    print 'Validate that the web URL UI correctly showed a GCP '
    print 'registration request during the previous "timeout" test'
    print 'If printer does not show a accept/cancel on Printer Web UI,'
    print 'Fail this test.'
    self.ManualPass(test_id, test_name, print_test=False)

  def test_04_DeviceRegistration(self):
    """Verify printer registration using Privet

    This test function actually executes three tests.
    1- User1 successfully registers
    2- User2 cannot register after User1 has begun registration process
    3- Printer correctly advertises as registered after registration
    """
    test_id = 'a2cefbe9-9c8b-4987-966c-c0da7343be17'
    test_name = 'testDeviceRegistration'

    test_id2 = '5b8b6d1d-618a-40c5-a16b-89de96b62262'
    test_name2 = 'testDeviceRegistrationMultipleUsers'

    test_id3 = '5c3ccd4d-6d04-40b7-8dad-89164964b42d'
    test_name3 = 'testDeviceRegistrationAdvertise'

    # Register user1
    print 'Initiating a registration attempt for User1'
    success = _device.StartPrivetRegister(user=Constants.USER['EMAIL'])
    try:
      self.assertTrue(success)
    except AssertionError:
      notes = 'Not able to register user1. Privet call /register/start failed'
      self.LogTest(test_id, test_name, 'Failed', notes)
      _device.CancelRegistration(user=Constants.USER['EMAIL'])
      raise
    else:
      try:
        success = _device.Register('User2 simultaneous registration attempt',
                                   user=Constants.USER2['EMAIL'],
                                   no_action=True, wait_for_user=False)
      except EnvironmentError:
        notes = ('Simultaneous registration failed. '
                 'getClaimToken() from User2\'s registration attempt '
                 'should not return the \'pending_user_action\' error msg. '
                 'The printer should reject User2\'s attempt since User1\'s '
                 'registration is already under way.')
        self.LogTest(test_id2, test_name2, 'Failed', notes)
        _device.CancelRegistration()
        raise
      else:
        try:
          self.assertFalse(success)
        except AssertionError:
          notes = 'Simultaneous registration succeeded.'
          self.LogTest(test_id2, test_name2, 'Failed', notes)
          raise
        else:
          notes = 'Simultaneous registration failed.'
          self.LogTest(test_id2, test_name2, 'Passed', notes)

          PromptUserAction('ACCEPT the registration request from %s on the '
                           'printer UI and wait...' % Constants.USER['EMAIL'])
          # Finish the registration process
          success = False
          if _device.GetPrivetClaimToken():
            if _device.ConfirmRegistration(_device.auth_token):
              success = _device.FinishPrivetRegister()
          try:
            self.assertTrue(success)
          except AssertionError:
            notes = 'User1 failed to register.'
            self.LogTest(test_id, test_name, 'Failed', notes)
            _device.CancelRegistration()
            raise
          else:
            print 'Waiting up to 2 minutes to complete the registration.'
            success = waitForAdvertisementRegStatus(Constants.PRINTER['NAME'],
                                                    True, 120)
            try:
              self.assertTrue(success)
            except AssertionError:
              notes = ('Registered device not found advertising '
                       'or found advertising as unregistered')
              self.LogTest(test_id3, test_name3, 'Failed', notes)
            else:
              notes = 'Registered device found advertising correctly'
              self.LogTest(test_id3, test_name3, 'Passed', notes)

            res = _gcp.Search(_device.name)
            try:
              self.assertTrue(res['printers'])
            except AssertionError:
              notes = 'Registered printer not found via the GCP Search API.'
              self.LogTest(test_id, test_name, 'Failed', notes)
              raise
            else:
              notes = ('Successfully found registered printer via the GCP '
                       'Search API')
              self.LogTest(test_id, test_name, 'Passed', notes)


class LocalDiscovery(LogoCert):
  """Tests Local Discovery functionality."""

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass(cls)
    _device.assertPrinterIsRegistered()
    LogoCert.GetDeviceDetails()

  def toggleOnLocalPrinting(self):
    """Turns on local printing"""
    print ('Re-enabling local printing in case it turned off along with '
           'local discovery')
    setting = {'pending': {'printer/local_printing_enabled': True}}
    res = _gcp.Update(_device.dev_id, setting=setting)

    if not res['success']:
      print ('Error turning on Local Printing. Please manually renable Local '
             'Printing and continue testing')
      return

    # Give the printer time to update.
    success = _gcp.WaitForUpdate(_device.dev_id,
                                 'printer/local_printing_enabled', True)

    if not success:
      print 'Failed to detect update before timing out.'
    else:
      print 'Local printing toggled on successfully'


  def testLocalDiscoveryToggle(self):
    """Verify printer behaves correctly when local discovery is toggled."""
    test_id = '72133bd8-c945-4364-aa2b-69a2ee088c59'
    test_name = 'testLocalDiscoveryToggle'
    notes = None
    notes2 = None

    setting = {'pending': {'local_discovery': False}}
    print "Toggling off local discovery"
    res = _gcp.Update(_device.dev_id, setting=setting)

    if not res['success']:
      notes = 'Error turning off Local Discovery.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      # Give printer time to update.
      success = _gcp.WaitForUpdate(_device.dev_id, 'local_discovery', False)
      try:
        self.assertTrue(success)
      except AssertionError:
        notes = 'Local Discovery was not disabled within 60 seconds.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        print 'Local Discovery successfully disabled'
        # Should not be any advertisements from the printer anymore
        print ('Listening for advertisements for 60 seconds, there should NOT '
               'be any from the printer')
        service = Wait_for_privet_mdns_service(60, Constants.PRINTER['NAME'],
                                               _logger)
        try:
          self.assertIsNone(service)
        except AssertionError:
          notes = 'Local Discovery disabled but privet advertisements detected.'
          self.LogTest(test_id, test_name, 'Failed', notes)
          print 'Attempting to toggle Local Discovery back on'
          setting = {'pending': {'local_discovery': True}}
          res = _gcp.Update(_device.dev_id, setting=setting)
          if not res['success']:
            print 'Update error, please manually re-enable Local Discovery'
          else:
            print 'Local Discovery successfully re-enabled'
          raise
        else:
          print 'Success, no printer advertisements detected'

    notes = 'Local Discovery successfully disabled'
    setting = {'pending': {'local_discovery': True}}
    print "Toggling on local discovery"
    res = _gcp.Update(_device.dev_id, setting=setting)

    if not res['success']:
      notes2 = 'Error turning on Local Discovery.'
      self.LogTest(test_id, test_name, 'Failed', notes + '\n' + notes2)
      raise
    else:
      # Give printer time to update.
      success = _gcp.WaitForUpdate(_device.dev_id, 'local_discovery', True)
      try:
        self.assertTrue(success)
      except AssertionError:
        notes2 = 'Local Discovery was not enabled within 60 seconds.'
        self.LogTest(test_id, test_name, 'Failed', notes2)
        self.toggleOnLocalPrinting()
        raise
      else:
        print  'Local Discovery successfully enabled'
        print ('Listening for advertisements for up to 60 seconds, '
               'there should be advertisements from the printer')
        service = Wait_for_privet_mdns_service(60, Constants.PRINTER['NAME'],
                                               _logger)
        try:
          self.assertIsNotNone(service)
        except AssertionError:
          notes2 = ('Local Discovery enabled, '
                    'but no privet advertisements detected.')
          self.LogTest(test_id, test_name, 'Failed', notes2)
          raise
        else:
          print 'Printer advertisements detected'
        finally:
          self.toggleOnLocalPrinting()

    notes2 = 'Local Discovery successfully enabled'
    notes = notes + '\n' + notes2
    self.LogTest(test_id, test_name, 'Passed', notes)

  def testPrinterOnAdvertiseLocally(self):
    """Verify printer sends start up advertisement packets when turned on.
       """
    test_id = '79ae01a8-9af8-4666-9186-fd822158bb30'
    test_name = 'testPrinterOnAdvertiseLocally'

    print 'This test should begin with the printer turned off.'
    PromptAndWaitForUserAction('Press ENTER once printer is powered off')

    PromptUserAction('Power on the printer and wait...')
    service = Wait_for_privet_mdns_service(300, Constants.PRINTER['NAME'],
                                           _logger)
    try:
      self.assertIsNotNone(service)
    except AssertionError:
      notes = 'Printer did not make privet packet.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Printer broadcast privet packet.'
      self.LogTest(test_id, test_name, 'Passed', notes)
    finally:
      # Get the new X-privet-token from the restart
      _device.GetPrivetInfo()


  def testPrinterOffSendGoodbyePacket(self):
    """Verify printer sends goodbye packet when turning off."""
    test_id = 'c76fb24b-22ce-4c44-a692-df91697b759c'
    test_name = 'testPrinterOffSendGoodbyePacket'
    if not Constants.CAPS['GOODBYE_PACKET']:
      notes = 'Printer does not send goodbye packet.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return

    print 'This test must start with the printer on and operational.'
    # Need a somewhat persistent browser (for the duration of this testcase
    # at least) to detect service removal
    mdns_browser = MDNS_Browser(_logger)
    service = mdns_browser.Wait_for_service_add(30, Constants.PRINTER['NAME'])
    try:
      self.assertIsNotNone(service)
    except AssertionError:
      notes = 'Printer did not send advertisement while powered on'
      self.LogTest(test_id, test_name, 'Failed')
      mdns_browser.Close()
      raise

    PromptUserAction('Turn off the printer and wait...')
    is_off = mdns_browser.Wait_for_service_remove(120,
                                                  Constants.PRINTER['NAME'])
    try:
      self.assertTrue(is_off)
    except AssertionError:
      notes = 'Printer did not send goodbye packet when powered off.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Printer sent goodbye packet when powered off.'
      self.LogTest(test_id, test_name, 'Passed', notes)
    finally:
      mdns_browser.Close()
      # Turn the printer back on
      PromptUserAction('Power on the printer and wait...')
      service = Wait_for_privet_mdns_service(300, Constants.PRINTER['NAME'],
                                             _logger)
      try:
        self.assertIsNotNone(service)
      except AssertionError:
        notes = 'Error receiving the power-on signal from the printer.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise


  def testPrinterIdleNoBroadcastPrivet(self):
    """Verify idle printer doesn't send mDNS broadcasts."""
    test_id = '288ca17e-65fc-4a9b-bf1f-59272a987927'
    test_name = 'testPrinterIdleNoBroadcastPrivet'

    print 'Ensure printer stays on and remains in idle state.'
    # Service TTL should not be updated if there are no advertisements from the
    # idle printer.
    mdns_browser = MDNS_Browser(_logger)
    service = mdns_browser.Wait_for_service_add(30, Constants.PRINTER['NAME'])

    try:
      self.assertIsNotNone(service)
    except AssertionError:
      mdns_browser.Close()
      notes = ('No printer mDNS broadcast packets found while printer '
               'is powered on.')
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      start_ttl = mdns_browser.Get_service_ttl(Constants.PRINTER['NAME'])
      # Monitor the local network for privet broadcasts.
      print 'Listening for network broadcasts for 60 seconds.'
      time.sleep(60)
      end_ttl = mdns_browser.Get_service_ttl(Constants.PRINTER['NAME'])
      try:
        self.assertTrue(start_ttl > end_ttl)
      except AssertionError:
        notes = ('Found printer mDNS broadcast packets containing privet while '
                 'printer is idle.')
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        notes = ('No printer mDNS broadcast packets containing privet were '
                 'found while printer is idle.')
        self.LogTest(test_id, test_name, 'Passed', notes)
      finally:
        mdns_browser.Close()



  def testUpdateLocalSettings(self):
    """Verify printer's local settings can be updated with Update API."""
    test_id = 'b88c27c6-e6fa-48e6-a19e-4e581c0f8e1c'
    test_name = 'testUpdateLocalSettings'
    # Get the current xmpp timeout value.

    orig = _device.cdd['local_settings']['current']['xmpp_timeout_value']
    new = orig + 600
    setting = {'pending': {'xmpp_timeout_value': new}}
    print 'Updating xmpp timeout value via the update interface'
    res = _gcp.Update(_device.dev_id, setting=setting)

    if not res['success']:
      notes = 'Error sending Update of local settings.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    print 'Successfully updated'
    success = _gcp.WaitForUpdate(_device.dev_id, 'xmpp_timeout_value', new)
    try:
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
        print 'Reverting the xmpp timeout value via the update interface'
        res = _gcp.Update(_device.dev_id, setting=setting)
        if res['success']:
          print 'Successfully updated'
          _gcp.WaitForUpdate(_device.dev_id, 'xmpp_timeout_value', orig)



class LocalPrinting(LogoCert):
  """Tests of local printing functionality."""
  def setUp(self):
    # Create a fresh CJT for each test case
    self.cjt = CloudJobTicket(_device.privet_info['version'])

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass(cls)
    _device.assertPrinterIsRegistered()
    LogoCert.GetDeviceDetails()

    # Need to download a few raster files that will be used to test local
    # printing. Different printers support different pwg-raster resolution
    # and colours. Leverage GCP for format conversion by submitting a job via
    # GCP, then downloading the raster files and saving them to disk
    getLocalPrintingRasterImages()

  def test_01_LocalPrintGuestUser(self):
    """Verify local print on a registered printer is available to guest user."""
    test_id = '465133e5-783d-4e60-882e-3c779d0421c0'
    test_name = 'testLocalPrintGuestUser'

    # New instance of device that is not authenticated - contains no auth-token
    guest_device = Device(_logger, None, None, privet_port=_device.port)
    guest_device.GetDeviceCDDLocally()

    job_id = guest_device.LocalPrint(test_name, Constants.IMAGES['PWG1'],
                                     self.cjt, 'image/pwg-raster')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Guest failed to print a pwg-raster image via local printing.'
      self.LogTest(test_id, test_name, 'Failed', notes)
    else:
      print 'Guest successfully printed a pwg-raster image via local printing.'
      print 'If not, fail this test.'
      self.ManualPass(test_id, test_name)


  def test_02_LocalPrintOwner(self):
    """Verify local print on a registered printer as the owner."""
    test_id = '38d7736d-20e4-4474-b32f-19414c32c9ab'
    test_name = 'testLocalPrintOwner'

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG1'], self.cjt,
                                'image/pwg-raster')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Owner failed to print a pwg-raster image via local printing.'
      self.LogTest(test_id, test_name, 'Failed', notes)
    else:
      print 'Owner successfully printed a pwg-raster image via local printing.'
      print 'If not, fail this test.'
      self.ManualPass(test_id, test_name)


  def test_03_LocalPrintingToggle(self):
    """Verify printer behaves correctly when local printing toggled."""
    test_id = 'fb331ad7-8ef1-4266-a35c-4ddf553e47e6'
    test_name = 'testLocalPrintingToggle'
    notes = None
    notes2 = None

    print 'Disabling local printing'
    setting = {'pending': {'printer/local_printing_enabled': False}}
    res = _gcp.Update(_device.dev_id, setting=setting)

    if not res['success']:
      notes = 'Error turning off Local Printing.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    # Give the printer time to update.
    success = _gcp.WaitForUpdate(_device.dev_id,
                                 'printer/local_printing_enabled', False)
    try:
      self.assertTrue(success)
    except AssertionError:
      notes = 'Failed to detect update before timing out.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    print 'Local print successfully turned off'

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG1'], self.cjt,
                                'image/pwg-raster')
    try:
      self.assertIsNone(job_id)
    except AssertionError:
      notes = 'Able to print via privet local printing when disabled.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Not able to print locally when disabled.'

    print 'Re-enabling local printing'
    setting = {'pending': {'printer/local_printing_enabled': True}}
    res = _gcp.Update(_device.dev_id, setting=setting)

    if not res['success']:
      notes2 = 'Error turning on Local Printing.'
      self.LogTest(test_id, test_name, 'Failed', notes2)
      raise

    # Give the printer time to update.
    success = _gcp.WaitForUpdate(_device.dev_id,
                                 'printer/local_printing_enabled', True)
    try:
      self.assertTrue(success)
    except AssertionError:
      notes = 'Failed to detect update before timing out.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    print 'Local print successfully enabled'

    success = _device.WaitForPrinterState('idle')
    try:
      self.assertTrue(success)
    except AssertionError:
      notes2 = 'Printer not in idle state after updates.'
      self.LogTest(test_id, test_name, 'Failed', notes2)
      raise

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG1'], self.cjt,
                                'image/pwg-raster')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes2 = 'Not able to print locally when enabled.'
      self.LogTest(test_id, test_name, 'Failed', notes2)
      raise
    else:
      notes2 = 'Able to print via privet local printing when re-enabled.'
      self.LogTest(test_id, test_name, 'Passed', notes + '\n' + notes2)


  def test_18_ConversionPrintingToggle(self):
    """Verify printer behaves correctly when conversion printing is toggled."""
    test_id = '991b6649-20ac-4d11-9853-e43dc60d1c49'
    test_name = 'testConversionPrintingToggle'
    notes = None
    notes2 = None

    print 'Disabling conversion printing'
    setting = {'pending': {'printer/conversion_printing_enabled': False}}
    res = _gcp.Update(_device.dev_id, setting=setting)

    if not res['success']:
      notes = 'Error turning off Conversion Printing.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    # Give the printer time to update.
    success = _gcp.WaitForUpdate(_device.dev_id,
                                 'printer/conversion_printing_enabled', False)
    try:
      self.assertTrue(success)
    except AssertionError:
      notes = 'Failed to detect update before timing out.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    print 'Conversion printing successfully turned off'

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['SVG1'], self.cjt,
                                'image/svg+xml', False)
    try:
      self.assertIsNone(job_id)
    except AssertionError:
      notes = 'Able to print via privet conversion printing when disabled.'
      notes += ' Check if the filetype svg is supported locally by the printer.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Not able to print file locally when conversion print is disabled.'

    print 'Re-enabling conversion printing'
    setting = {'pending': {'printer/conversion_printing_enabled': True}}
    res = _gcp.Update(_device.dev_id, setting=setting)

    if not res['success']:
      notes2 = 'Error turning on Conversion Printing.'
      self.LogTest(test_id, test_name, 'Failed', notes2)
      raise

    # Give the printer time to update.
    success = _gcp.WaitForUpdate(_device.dev_id,
                                 'printer/conversion_printing_enabled', True)
    try:
      self.assertTrue(success)
    except AssertionError:
      notes = 'Failed to detect update before timing out.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    print 'Local print successfully enabled'

    success = _device.WaitForPrinterState('idle')
    try:
      self.assertTrue(success)
    except AssertionError:
      notes2 = 'Printer not in idle state after updates.'
      self.LogTest(test_id, test_name, 'Failed', notes2)
      raise

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['SVG1'], self.cjt,
                                'image/svg+xml', False)
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes2 = 'Not able to print an svg file locally when conversion printing is enabled.'
      self.LogTest(test_id, test_name, 'Failed', notes2)
      raise
    else:
      notes2 = 'Able to print an svg file via privet local printing when conversion printing is re-enabled.'
      self.LogTest(test_id, test_name, 'Passed', notes + '\n' + notes2)


  def test_04_LocalPrintHTML(self):
    """Verify printer can local print HTML file."""
    test_id = 'c93ed781-d0b5-44bc-89e2-4e5b31bafd3d'
    test_name = 'testLocalPrintHTML'

    if 'text/html' not in _device.supported_types:
      self.LogTest(test_id, test_name, 'Skipped', 'No local print Html support')
      return

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['HTML1'], self.cjt,
                                'text/html')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing %s' % Constants.IMAGES['HTML1']
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'HTML file should be printed.'
      print 'Fail this test if print out has errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def test_05_LocalPrintJPG(self):
    """Verify a 1 page JPG file prints using Local Printing."""
    test_id = '824f95f8-9380-4c37-9552-f6e56e2c8463'
    test_name = 'testLocalPrintJPG'

    if ('image/jpeg' not in _device.supported_types and
        'image/pjpeg' not in _device.supported_types):
      self.LogTest(test_id, test_name, 'Skipped', 'No local print Jpg support')
      return

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['JPG12'], self.cjt,
                                'image/jpeg')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing %s' % Constants.IMAGES['JPG12']
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'JPG file should be printed.'
      print 'Fail this test if print out has errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def test_06_LocalPrintPNG(self):
    """Verify a 1 page PNG file prints using Local Printing."""
    test_id = '90c3f594-6792-4c07-b747-ae217ff8178a'
    test_name = 'testLocalPrintPNG'

    if 'image/png' not in _device.supported_types:
      self.LogTest(test_id, test_name, 'Skipped', 'No local print PNG support')
      return

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PNG6'], self.cjt,
                                'image/png')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing %s' % Constants.IMAGES['PNG6']
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'PNG file should be printed.'
      print 'Fail this test if print out has errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def test_07_LocalPrintGIF(self):
    """Verify a 1 page GIF file prints using Local Printing."""
    test_id = '39720f61-f142-4ef5-ba55-1efaad8a89dd'
    test_name = 'testLocalPrintGIF'

    if 'image/gif' not in _device.supported_types:
      self.LogTest(test_id, test_name, 'Skipped', 'No local print Gif support')
      return

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['GIF4'], self.cjt,
                                'image/gif')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing %s' % Constants.IMAGES['GIF4']
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'GIF file should be printed.'
      print 'Fail this test if print out has errors or quality issues.'
      self.ManualPass(test_id, test_name)

  def test_08_LocalPrintPDF(self):
    """Verify a 1 page PDF file prints using Local Printing."""
    test_id = 'd6497ac5-4d15-46d4-8aee-261890180dca'
    test_name = 'testLocalPrintPDF'

    if 'application/pdf' not in _device.supported_types:
      self.LogTest(test_id, test_name, 'Skipped', 'No local print PDF support')
      return

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PDF9'], self.cjt,
                                'application/pdf')
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

  def test_09_LocalPrintPDFDuplex(self):
    """Verify printer respects duplex option for PDFs in local print."""
    test_id = 'c1b3136f-e6c1-413d-977d-c295a8351703'
    test_name = 'testLocalPrintPDFDuplex'

    if 'application/pdf' not in _device.supported_types:
      self.LogTest(test_id, test_name, 'Skipped', 'No local print PDF support')
      return

    if not Constants.CAPS['DUPLEX']:
      self.LogTest(test_id, test_name, 'Skipped', 'No Duplex support')
      return

    self.cjt.AddDuplexOption(GCPConstants.LONG_EDGE)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PDF10'], self.cjt,
                                'application/pdf')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error printing with LONG_EDGE option in local printing.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    PromptAndWaitForUserAction('Press ENTER when the document is completely '
                               'printed')

    self.cjt.AddDuplexOption(GCPConstants.SHORT_EDGE)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PDF10'], self.cjt,
                                'application/pdf')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error printing with SHORT_EDGE option in local printing.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'The 1st print job should be printed 2-sided along the long edge.'
      print 'The 2nd print job should be printed 2-sided along the short edge.'
      print 'If not, fail this test.'
      self.ManualPass(test_id, test_name)


  def test_10_LocalPrintPDFMargins(self):
    """Verify printer respects margins option for PDFs in local print."""
    test_id = 'a9c482e0-9494-469c-a391-d70c171bd9c2'
    test_name = 'testLocalPrintPDFMargins'

    if 'application/pdf' not in _device.supported_types:
      self.LogTest(test_id, test_name, 'Skipped', 'No local print PDF support')
      return

    if not Constants.CAPS['MARGIN']:
      self.LogTest(test_id, test_name, 'Skipped', 'No Margin support')
      return

    self.cjt.AddMarginOption(0, 0, 0, 0)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PDF9'], self.cjt,
                                'application/pdf')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing with no margins.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    self.cjt.AddMarginOption(50000, 50000, 50000, 50000)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PDF9'], self.cjt,
                                'application/pdf')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing with minimum margins.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    print 'The 1st print job should have no margins.'
    print 'The 2nd print job should have minimum margins.'
    print 'If the margins are not correct, fail this test.'
    self.ManualPass(test_id, test_name)

  def test_11_LocalPrintPDFLayout(self):
    """Verify printer respects layout settings for PDFs in local print."""
    test_id = '151eca79-23c5-4fad-855d-2b5aad7dd9c5'
    test_name = 'testLocalPrintPDFLayout'

    if 'application/pdf' not in _device.supported_types:
      self.LogTest(test_id, test_name, 'Skipped', 'No local print PDF support')
      return

    self.cjt.AddPageOrientationOption(GCPConstants.PORTRAIT)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PDF9'], self.cjt,
                                'application/pdf')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing with portrait layout.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    self.cjt.AddPageOrientationOption(GCPConstants.LANDSCAPE)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PDF9'], self.cjt,
                                'application/pdf')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing with landscape layout.'
      self.LogTest(test_id, test_name, 'Failed', notes)
    else:
      print 'The 1st print job should be printed in portrait layout.'
      print 'The 2nd print job should be printed in landscape layout.'
      print 'If the layout is not correct, fail this test.'
      self.ManualPass(test_id, test_name)

  def test_12_LocalPrintPDFPageRange(self):
    """Verify printer respects page range for PDFs in local print."""
    test_id = 'f3b2428b-2c48-411d-a7b6-c336452b36b6'
    test_name = 'testLocalPrintPDFPageRange'

    if 'application/pdf' not in _device.supported_types:
      self.LogTest(test_id, test_name, 'Skipped', 'No local print PDF support')
      return

    self.cjt.AddPageRangeOption(2, end=2)
    self.cjt.AddPageRangeOption(4, end=6)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PDF1'], self.cjt,
                                'application/pdf')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error printing with page range set to page 2 and 4-6.'
      self.LogTest(test_id, test_name, 'Failed', notes)
    else:
      print 'The print job should only print pages 2, 4, 5, 6.'
      print 'If this is not the case, fail this test.'
      self.ManualPass(test_id, test_name)

  def test_13_LocalPrintPDFCopies(self):
    """Verify printer respects copy option for PDFs in local print."""
    test_id = '1eb21d57-59f4-457e-a097-d5c4d584502f'
    test_name = 'testLocalPrintPDFCopies'

    if 'application/pdf' not in _device.supported_types:
      self.LogTest(test_id, test_name, 'Skipped', 'No local print PDF support')
      return

    if not Constants.CAPS['COPIES_LOCAL']:
      notes = 'Printer does not support copies option.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return

    self.cjt.AddCopiesOption(2)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PDF9'], self.cjt,
                                'application/pdf')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing with copies option.'
      self.LogTest(test_id, test_name, 'Failed', notes)
    else:
      print 'The print job should have printed 2 copies.'
      print 'If 2 copies are not printed, fail this test.'
      self.ManualPass(test_id, test_name)

  def test_14_LocalPrintPDFColorSelect(self):
    """Verify printer respects color option for PDFs in local print."""
    test_id = 'e12ea6cc-d33f-4f94-a435-694704f7ba72'
    test_name = 'testLocalPrintPDFColorSelect'

    if 'application/pdf' not in _device.supported_types:
      self.LogTest(test_id, test_name, 'Skipped', 'No local print PDF support')
      return

    if not Constants.CAPS['COLOR']:
      notes = 'Printer does not support color printing.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return

    self.cjt.AddColorOption(GCPConstants.COLOR)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PDF9'], self.cjt,
                                'application/pdf')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing with color selected.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    PromptAndWaitForUserAction('Press ENTER when page is printed')

    self.cjt.AddColorOption(GCPConstants.MONOCHROME)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PDF9'], self.cjt,
                                'application/pdf')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing with monochrome selected.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'The 1st print job should be printed in color.'
      print 'The 2nd print job should be printed in monochrome.'
      print 'If not, fail this test.'
      self.ManualPass(test_id, test_name)

  def test_15_LocalPrintPWGDuplex(self):
    """Verify printer respects duplex option for PWGs in local print."""
    test_id = 'ebd264ed-e9ac-4bff-9a8b-d1b4c5af477e'
    test_name = 'testLocalPrintPWGDuplex'

    if not Constants.CAPS['DUPLEX']:
      self.LogTest(test_id, test_name, 'Skipped', 'No Duplex support')
      return

    self.cjt.AddDuplexOption(GCPConstants.LONG_EDGE)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG2'], self.cjt,
                                'image/pwg-raster')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error printing with LONG_EDGE option in local printing.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    PromptAndWaitForUserAction('Press ENTER when the document is completely '
                               'printed')

    self.cjt.AddDuplexOption(GCPConstants.SHORT_EDGE)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG2'], self.cjt,
                                'image/pwg-raster')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error printing with SHORT_EDGE option in local printing.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Both print jobs should be printed in duplex regardless of edge'
      print 'If not, fail this test.'
      self.ManualPass(test_id, test_name)

  def test_16_LocalPrintPWGColorSelect(self):
    """Verify printer respects color option for PWGs in local print."""
    test_id = 'bfd5ee5e-4bef-4e8e-b64a-63fef421ae28'
    test_name = 'testLocalPrintPWGColorSelect'

    if not Constants.CAPS['COLOR']:
      notes = 'Printer does not support color printing.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return

    self.cjt.AddColorOption(GCPConstants.COLOR)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG1'], self.cjt,
                                'image/pwg-raster')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing with color selected.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    PromptAndWaitForUserAction('Press ENTER when page is printed')

    self.cjt.AddColorOption(GCPConstants.MONOCHROME)
    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG1'], self.cjt,
                                'image/pwg-raster')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing with monochrome selected.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'The 1st print job should be printed in color.'
      print 'The 2nd print job should be printed in monochrome.'
      print 'If not, fail this test.'
      self.ManualPass(test_id, test_name)


  def test_17_LocalPrintPWG(self):
    """Verify printer can successfully print PWGs in local print."""
    test_id = '013fb153-940a-45d2-a5fd-7112d4d1198d'
    test_name = 'testLocalPrintPWG'

    job_id = _device.LocalPrint(test_name, Constants.IMAGES['PWG1'], self.cjt,
                                'image/pwg-raster')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = 'Error local printing PWG raster file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'PWG Raster file should print successfully.'
      print 'If not, fail this test.'
      self.ManualPass(test_id, test_name)


class PostRegistration(LogoCert):
  """Tests to run after _device is registered."""

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass(cls)
    _device.assertPrinterIsRegistered()
    LogoCert.GetDeviceDetails()

  def testDeviceDetails(self):
    """Verify printer details are provided to Cloud Print Service."""
    test_id = '597a2e5d-9fe8-455b-aa3a-2f063621d2b2'
    test_name = 'testDeviceDetails'

    try:
      self.assertIsNotNone(_device.name)
    except AssertionError:
      notes = 'Error finding device in via privet.'
      self._logger.error('Check your printer model in the _config file.')
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'Found printer details via privet.'
      _device.GetDeviceCDD(_device.dev_id)
      self.LogTest(test_id, test_name, 'Passed', notes)


  def testRegisteredDevicePoweredOffShowsOffline(self):
    """Verify device shows offline when it is powered off."""
    test_id = '9bb02ec3-b3f5-4d26-98dd-9b493bfe226e'
    test_name = 'testRegisteredDevicePoweredOffShowsOffline'

    # Make sure device is in 'online' state before this test
    print 'Waiting up to 120 seconds for printer to be in online state.'
    print 'Polling every 5 seconds'
    end = time.time() + 120
    while time.time() < end:
      _device.GetDeviceDetails()
      if 'ONLINE' in _device.status:
        break
      # Not using Constant.SLEEP['POLL'] here since the status update
      # actually takes a while
      time.sleep(5)

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
      PromptAndWaitForUserAction('Press ENTER once printer is powered off')
      print 'Waiting up to 10 minutes for printer status update.'
      print 'Polling every 5 seconds'
      end = time.time() + 600
      while time.time() < end:
        _device.GetDeviceDetails()
        if 'OFFLINE' in _device.status:
          break
        # Not using Constant.SLEEP['POLL'] here since the status update
        # actually takes a while
        time.sleep(5)
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
        PromptAndWaitForUserAction('Press ENTER to continue this testcase.')
        PromptUserAction('Power on the printer and wait...')
        service = Wait_for_privet_mdns_service(300, Constants.PRINTER['NAME'],
                                               _logger)
        try:
          self.assertIsNotNone(service)
        except AssertionError:
          notes = 'Error receiving the power-on signal from the printer.'
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        # Get the new X-privet-token from the restart
        _device.GetPrivetInfo()

  def testRegisteredDeviceNotDiscoverableAfterPowerOn(self):
    """Verify power cycled registered device advertises as registered."""
    test_id = 'f95f07e3-6c51-49c5-8a14-29b51c5e5695'
    test_name = 'testRegisteredDeviceNotDiscoverableAfterPowerOn'

    PromptAndWaitForUserAction('Press ENTER once printer is powered off')

    PromptUserAction('Power on the printer and wait...')
    success = waitForAdvertisementRegStatus(Constants.PRINTER['NAME'],
                                            True, 300)
    try:
      self.assertTrue(success)
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
    _device.assertPrinterIsRegistered()
    LogoCert.GetDeviceDetails()

  def GetErrorMsg(self, printer_states):
    """Loop through printer messages and find the first error message.

    Args:
      printer_states: dictionary, contains varies printer state objects
    Returns:
      string: error message if found, else None
    """
    for key, val in printer_states.iteritems():
      for state in val:
        if state['severity'] != 'NONE':
          return state['message'].lower()
    return None


  def VerifyUiStateMessage(self, test_id, test_name, keywords_list,
                           suffixes = None):
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
      elif 'printer' in _device.cdd['uiState']:
        uiMsg = self.GetErrorMsg(_device.cdd['uiState']['printer'])
        if uiMsg is None:
          notes = ('No error messages found in uistate[caption] or '
                   'uiState[printer]')
          self.LogTest(test_id, test_name, 'Failed', notes)
          return False
        uiMsg = re.sub(r' \(.*\)$', '', uiMsg)
        uiMsg.strip()
      else:
        notes = 'No \'caption\' attribute found inside uiState'
        self.LogTest(test_id, test_name, 'Failed', notes)
        return False
    else:
      notes = 'No \'uiState\' attribute found inside cdd'
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
        notes = ('required keyword(s) "%s" not in UI state message: %s' %
                 (keywords, _device.cdd['uiState']['caption']))
        self.LogTest(test_id, test_name, 'Failed', notes)
        return False

    if suffixes is not None:
      # check for suffixes
      if not uiMsg.endswith(suffixes):
        notes = ('None of the required suffix(s) "%s" are found in the UI state'
                 ' message: %s' % (keywords, _device.cdd['uiState']['caption']))
        self.LogTest(test_id, test_name, 'Failed', notes)
        return False

    self.LogTest(test_id, test_name, 'Passed')
    return True

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
      notes = ('UI shows error state with message: %s' %
               _device.cdd['uiState']['caption'])
      self.LogTest(test_id, test_name, 'Failed', notes)
      return False

  def testLostNetworkConnection(self):
    """Verify printer that loses network connection reconnects properly."""
    test_id = '8c67068a-e8c0-4b3f-b85d-52977f62a3fd'
    test_name = 'testLostNetworkConnection'

    print 'Test printer handles connection status when reconnecting to network.'
    PromptAndWaitForUserAction('Press ENTER once printer loses '
                               'network connection.')
    Sleep('NETWORK_DETECTION')
    print 'Now reconnect printer to the network.'
    PromptAndWaitForUserAction('Press ENTER once printer has '
                               'network connection.')
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
    test_id = '09f3f838-922b-4526-b5b8-bd83806816d0'
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
      # Check state message.
      # Some input trays may not be opened and be normally empty.
      if not self.VerifyUiStateMessage(test_id, test_name, ['input/tray'],
                                       suffixes=('is open',
                                                 'is empty',
                                                 '% full')):
        raise

    test_id2 = 'a158fe6a-125f-46e2-a382-9189eb06b5f0'
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
    test_id = 'bb5048de-cf93-487e-a44b-9366721fa39c'
    test_name = 'testNoMediaInTray'

    if not Constants.CAPS['MEDIA_SENSOR']:
      notes = 'Printer does not have a paper tray sensor.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    print 'Remove all media from the paper tray.'
    PromptAndWaitForUserAction('Press ENTER once all media is removed.')
    Sleep('PRINTER_STATE')
    _device.GetDeviceDetails()
    if not self.VerifyUiStateMessage(test_id, test_name, ['input/tray'],
                                     suffixes=('is empty')):
      raise

    test_id2 = 'a0387dea-6b87-4418-9489-41c9b4cb68d9'
    test_name2 = 'testMediaInTray'
    print 'Place media in all paper trays.'
    PromptAndWaitForUserAction('Press ENTER once you have placed paper '
                               'in paper tray.')
    Sleep('PRINTER_STATE')
    _device.GetDeviceDetails()
    if not self.VerifyUiStateHealthy(test_id2, test_name2):
      raise

  def testRemoveTonerCartridge(self):
    """Verify missing/empty toner cartridge is reported correctly."""
    test_id = '13c3cccd-0d72-4a04-8462-d4fa16992338'
    test_name = 'testRemoveTonerCartridge'

    if not Constants.CAPS['TONER']:
      notes = 'Printer does not contain ink toner.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return True
    print 'Remove the (or one) toner cartridge from the printer.'
    PromptAndWaitForUserAction('Press ENTER once the toner cartridge '
                               'is removed.')
    Sleep('PRINTER_STATE')
    _device.GetDeviceDetails()
    try:
      self.assertTrue(_device.error_state)
    except AssertionError:
      notes = 'Printer is not in error state with missing toner cartridge.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      PromptAndWaitForUserAction(
        'Press ENTER once toner is replaced in printer to continue testing.')
      raise
    else:
      if not self.VerifyUiStateMessage(test_id, test_name, ['ink/toner'],
                                       ('is removed',
                                        'is empty',
                                        'is low',
                                        'pages remaining',
                                        '%')):
        PromptAndWaitForUserAction(
          'Press ENTER once toner is replaced in printer to continue testing.')
        raise

    test_id2 = 'cbe4b5ac-7edb-41f3-a816-98aaf9522c83'
    test_name2 = 'testExhaustTonerCartridge'

    if not Constants.CAPS['EMPTY_INK_SENSOR']:
      notes = 'Printer does not support empty toner detection.'
      self.LogTest(test_id2, test_name2, 'Skipped', notes)
    else:
      print 'Insert an empty toner cartridge in printer.'
      PromptAndWaitForUserAction('Press ENTER once an empty toner cartridge is '
                                 'in printer.')
      Sleep('PRINTER_STATE')
      _device.GetDeviceDetails()
      try:
        self.assertTrue(_device.error_state)
      except AssertionError:
        notes = 'Printer is not in error state with empty toner.'
        self.LogTest(test_id2, test_name2, 'Failed', notes)
        PromptAndWaitForUserAction(
          'Press ENTER once original toner is replaced in printer to continue '
          'testing.')
        raise
      else:
        if not self.VerifyUiStateMessage(test_id2, test_name2, ['ink/toner'],
                                         ('is removed',
                                          'is empty',
                                          'is low',
                                          'pages remaining',
                                          '%')):
          PromptAndWaitForUserAction(
            'Press ENTER once original toner is replaced in printer to '
            'continue testing.')
          raise

    test_id3 = 'd2bd8b57-c7c1-45b4-b458-1800c240a93a'
    test_name3 = 'testReplaceMissingToner'
    print ('Verify that the error is fixed by replacing the original '
           'toner cartridge.')
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
    test_id = 'fd368e65-3143-48d8-83a9-24199511f262'
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
      if not self.VerifyUiStateMessage(test_id, test_name, ['Door/Cover'],
                                       suffixes=('is open')):
        raise

    test_id2 = '57b2fd84-5328-4a39-a70e-e0ae250ff109'
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
    test_id = '1ccbf64c-17bc-4464-a943-f9b94d3f6a3f'
    test_name = 'testPaperJam'

    print 'Cause the printer to become jammed with paper.'
    PromptAndWaitForUserAction('Press ENTER once the printer '
                               'has become jammed.')
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

    test_id2 = 'd1b77fe3-9d1d-4d08-917a-6c7254ea3bd2'
    test_name2 = 'testRemovePaperJam'
    print 'Now clear the paper jam.'
    PromptAndWaitForUserAction('Press ENTER once the paper jam is clear '
                               'from printer.')
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
    self.cjt = CloudJobTicket(_device.details['gcpVersion'])

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass(cls)
    _device.assertPrinterIsRegistered()
    LogoCert.GetDeviceDetails()

  def testOnePagePrintJobState(self):
    """Verify a 1 page print job is reported correctly."""
    test_id = 'a848d29b-1dd6-422a-ab3e-5f370083d278'
    test_name = 'testOnePagePrintJobState'
    print 'Wait for this one page print job to finish.'

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['JPG6'],
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing one page JPG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        job = _gcp.WaitJobStateIn(output['job']['id'],
                                  _device.dev_id,
                                 GCPConstants.DONE,
                                 timeout=Constants.TIMEOUT['PRINTING'])
      except AssertionError:
        notes = ('Job state did not transition to %s within %s seconds.' %
                 (GCPConstants.DONE, Constants.TIMEOUT['PRINTING']))
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
    test_id = '09be688d-03c9-47a4-afaa-0c87b12c9608'
    test_name = 'testMultiPageJobState'
    print 'Wait until job starts printing 7 page PDF file...'

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1.7'], test_name,
                         self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error while printing 7 page PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print ('When printer starts printing, '
             'Job State should transition to in progress.')
      try:
        _gcp.WaitJobStateIn(output['job']['id'], _device.dev_id,
                            GCPConstants.IN_PROGRESS)
      except AssertionError:
        notes = 'Job is not "In progress" while job is still printing.'
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        try:
          job = _gcp.WaitJobStateIn(output['job']['id'],
                                    _device.dev_id,
                                    GCPConstants.DONE,
                                   timeout=Constants.TIMEOUT['PRINTING'])
        except AssertionError:
          notes = ('Job state did not transition to %s within %s seconds.' %
                   (GCPConstants.DONE, Constants.TIMEOUT['PRINTING']))
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
    test_id = 'e679616c-d363-4f86-882b-d274dde44c46'
    test_name = 'testJobDeletionRecovery'

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1.7'], test_name,
                         self.cjt)

    if output['success']:
      PromptAndWaitForUserAction('Press ENTER once the first page prints out.')
      print "Deleting job mid print"
      delete_res = _gcp.DeleteJob(output['job']['id'])
      if delete_res['success']:
        print "Job deleted successfully"
        print "Give the printer time to finish printing the deleted job"
        # Since it's PDF file give the job time to finish printing.
        PromptAndWaitForUserAction('Press ENTER once printer is '
                                   'finished printing')
        print "Printing another job"
        output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG7'],
                             test_name, self.cjt)
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
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
    else:
      notes = 'Error printing multi-page PDF file.'
      _logger.error(notes)
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

  def testJobStateEmptyInputTray(self):
    """Validate proper /control msg when input tray is empty."""
    test_id = '8ccc4b5e-becc-466f-87be-3fd9782a4769'
    test_name = 'testJobStateEmptyInputTray'
    print 'Empty the input tray of all paper.'

    PromptAndWaitForUserAction('Press ENTER once input tray has been emptied.')

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1.7'], test_name,
                         self.cjt)

    if output['success']:
      try:
        job = _gcp.WaitJobStateNotIn(output['job']['id'], _device.dev_id,
                                    [GCPConstants.QUEUED,
                                     GCPConstants.IN_PROGRESS],
                                     timeout = Constants.TIMEOUT['PRINTING'])
      except AssertionError:
        notes = ('Job not found or status transitioned into Queued or '
                 'In Progress within %s seconds.' %
                 (Constants.TIMEOUT['PRINTING']))
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        try:
          self.assertEqual(job['semanticState']['state']['type'],
                           GCPConstants.STOPPED)
        except AssertionError:
          notes = 'Print Job is not in Stopped state.'
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        else:
          job_state_msg = job['uiState']['cause']
          notes = 'Job State Error msg: %s' % job_state_msg
          try:
            #TODO: Do we really want to fail here if 'tray' is not in the msg?
            self.assertIn('tray', job_state_msg)
          except AssertionError:
            notes += ('The Job State error message does not contain tray.')
            notes += ('Note that the error message may be ok.')
            self.LogTest(test_id, test_name, 'Failed', notes)
            raise
          else:
            PromptAndWaitForUserAction('Press ENTER after placing the papers '
                                       'back in the input tray.')
            print ('After placing the paper back, Job State should transition '
                   'to in progress.')
            try:
              job = _gcp.WaitJobStateIn(output['job']['id'],
                                        _device.dev_id,
                                        GCPConstants.IN_PROGRESS)
            except AssertionError:
              notes = 'Job is not in progress: %s' % job['status']
              _logger.error(notes)
              self.LogTest(test_id, test_name, 'Failed', notes)
              raise
            else:
              print 'Wait for the print job to finish.'
              try:
                job = _gcp.WaitJobStateIn(output['job']['id'],
                                          _device.dev_id,
                                          GCPConstants.DONE,
                                          timeout= Constants.TIMEOUT['PRINTING'])
              except AssertionError:
                notes = ('Job state did not transition to %s within '
                         '%s seconds.' %
                         (GCPConstants.DONE, Constants.TIMEOUT['PRINTING']))
                self.LogTest(test_id, test_name, 'Failed', notes)
                raise
              else:
                notes = 'Job state: %s' % job['status']
                self.LogTest(test_id, test_name, 'Passed', notes)
    else:
      notes = 'Error printing PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

  def testJobStateMissingToner(self):
    """Validate proper /control msg when toner or ink cartridge is missing."""
    test_id = 'ad9ddb5a-57cf-404c-93cb-c576943b3efd'
    test_name = 'testJobStateMissingToner'

    if not Constants.CAPS['TONER']:
      notes = 'printer does not contain toner ink.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    print 'Remove ink cartridge or toner from the printer.'
    PromptAndWaitForUserAction('Press ENTER once the toner is removed.')

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1.7'], test_name,
                         self.cjt)
    if output['success']:
      try:
        job = _gcp.WaitJobStateNotIn(output['job']['id'], _device.dev_id,
                                    [GCPConstants.QUEUED,
                                     GCPConstants.IN_PROGRESS],
                                     timeout = Constants.TIMEOUT['PRINTING'])
      except AssertionError:
        notes = ('Job not found or status transitioned into Queued or '
                 'In Progress within %s seconds.' %
                 (Constants.TIMEOUT['PRINTING']))
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        try:
          self.assertEqual(job['semanticState']['state']['type'],
                           GCPConstants.STOPPED)
        except AssertionError:
          notes = 'Print Job is not in Stopped state.'
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
            PromptAndWaitForUserAction('Press ENTER once the toner or ink is '
                                       'placed back in printer.')
            print ('After placing the toner back, Job State should transition '
                   'to in progress.')
            try:
              job = _gcp.WaitJobStateIn(output['job']['id'],
                                        _device.dev_id,
                                        GCPConstants.IN_PROGRESS)
            except AssertionError:
              notes = 'Job is not in progress: %s' % job['status']
              _logger.error(notes)
              self.LogTest(test_id, test_name, 'Failed', notes)
              raise
            else:
              print 'Wait for the print job to finish.'
              try:
                job = _gcp.WaitJobStateIn(output['job']['id'],
                                          _device.dev_id,
                                          GCPConstants.DONE,
                                          timeout=
                                          Constants.TIMEOUT['PRINTING'])
              except AssertionError:
                notes = ('Job state did not transition to '
                         '%s within %s seconds.' %
                         (GCPConstants.DONE, Constants.TIMEOUT['PRINTING']))
                self.LogTest(test_id, test_name, 'Failed', notes)
                raise
              else:
                notes = 'Job state: %s' % job['status']
                self.LogTest(test_id, test_name, 'Passed', notes)
    else:
      notes = 'Error printing PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

  def testJobStateNetworkOutage(self):
    """Validate proper /control msg when there is network outage."""
    test_id = 'f7b647ba-5b73-4d71-96b9-d1ae506ee0c5'
    test_name = 'testJobStateNetworkOutage'
    print ('This test requires the printer to be disconnected from the network '
           'after the first page is printed.')
    PromptAndWaitForUserAction('Press ENTER when you are prepared to disconnect '
                               'the network to begin the printjob')

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF1.7'], test_name,
                         self.cjt)

    if output['success']:
      job_id = output['job']['id']
      PromptAndWaitForUserAction('Wait for one page to print. Press ENTER once network is disconnected.')

      try:
        _gcp.WaitJobStateIn(job_id, _device.dev_id, GCPConstants.IN_PROGRESS)
      except AssertionError:
        notes = ('Job state did not transition to %s within %s seconds.' %
                 (GCPConstants.IN_PROGRESS, 30))
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        print 'Re-establish network connection to printer.'
        PromptAndWaitForUserAction('Press ENTER once printer has successfully '
                                   'established a connection to the network.')
        print ('Once network is reconnected, '
               'Job state should transition to in progress.')
        try:
          _gcp.WaitJobStateIn(job_id, _device.dev_id, GCPConstants.IN_PROGRESS)
        except AssertionError:
          notes = ('Job state did not transition to %s within %s seconds.' %
                   (GCPConstants.IN_PROGRESS, 30))
          self.LogTest(test_id, test_name, 'Failed', notes)
          raise
        else:
          print 'Wait for the print job to finish.'
          try:
            job = _gcp.WaitJobStateIn(output['job']['id'],
                                      _device.dev_id,
                                     [GCPConstants.DONE,
                                      GCPConstants.ABORTED],
                                      timeout=Constants.TIMEOUT['PRINTING'])
          except AssertionError:
            notes = ('Job state did not transition to Done within %s seconds '
                     'of starting print job.'
                     % (Constants.TIMEOUT['PRINTING']))
            self.LogTest(test_id, test_name, 'Failed', notes)
            raise
          else:
            notes = 'Job state: %s' % job['status']
            self.LogTest(test_id, test_name, 'Passed', notes)
    else:
      notes = 'Error printing PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

  def testJobStateWithPaperJam(self):
    """Validate proper behavior of print job when paper is jammed."""
    test_id = '167ecac1-db45-4e2c-9352-98bff432d03b'
    test_name = 'testJobStateWithPaperJam'

    print 'This test will validate job state when there is a paper jam.'
    print 'Place page inside print path to cause a paper jam.'
    PromptAndWaitForUserAction('Press ENTER once printer reports paper jam.')

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF9'], test_name,
                         self.cjt)

    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing %s' % Constants.IMAGES['PDF9']
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print 'Verifying job is reported in error state.'
      try:
        _gcp.WaitJobStateIn(output['job']['id'],
                            _device.dev_id,
                            GCPConstants.STOPPED)
      except AssertionError:
        notes = ('Job state did not transition to %s within %s seconds.'
                 % (GCPConstants.STOPPED, 60))
        _logger.error(notes)
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        print 'Now clear the print path so the printer is no longer jammed.'
        PromptAndWaitForUserAction('Press ENTER once printer is clear of jam.')
        print 'Verify print job prints after paper jam is cleared.'
        self.ManualPass(test_id, test_name)
    finally:
      # Make sure printer is no longer in an error state before continuing
      print 'Before continuing, make sure printer is no longer in error state'
      PromptAndWaitForUserAction('Press ENTER to continue testing.')

  def testJobStateIncorrectMediaSize(self):
    """Validate proper behavior when incorrect media size is selected."""
    test_id = 'edea71b1-4cbe-47a5-bc96-93e33b68c0b7'
    test_name = 'testJobStateIncorrectMediaSize'
    print 'This test is designed to select media size that is not available.'
    print 'The printer should prompt the user to enter the requested size.'
    print 'Load input tray with letter sized paper.'

    PromptAndWaitForUserAction('Press ENTER once paper tray loaded with ONLY '
                               'letter sized paper.')

    self.cjt.AddSizeOption(GCPConstants.A4_HEIGHT, GCPConstants.A4_WIDTH)

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG7'], test_name,
                         self.cjt)

    print 'Attempting to print with A4 media size.'
    print 'Fail this test if printer does not warn user to load correct size'
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing %s' % Constants.IMAGES['PNG7']
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      PromptAndWaitForUserAction('Verify printer status, then press ENTER')
      print 'Now load printer with A4 size paper.'
      PromptAndWaitForUserAction('After placing the correct paper size, '
                                 'press ENTER')
      print 'Printer should continue printing and complete the print job.'
      try:
        _gcp.WaitJobStateIn(output['job']['id'],
                            _device.dev_id,
                            GCPConstants.DONE,
                            timeout=Constants.TIMEOUT['PRINTING'])
      except AssertionError:
        notes = ('Job state did not transition to %s within %s seconds.'
                 % (GCPConstants.DONE, Constants.TIMEOUT['PRINTING']))
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        self.ManualPass(test_id, test_name)
    finally:
      PromptAndWaitForUserAction('Press ENTER once printer is loaded with '
                                 'letter size paper to continue testing. ')

  def testMultipleJobsPrint(self):
    """Verify multiple jobs in queue are all printed."""
    test_id = '48389666-80ae-41a9-a9ab-3112a42c84bd'
    test_name = 'testMultipleJobsPrint'
    print 'This tests that multiple jobs in print queue are printed.'

    for _ in xrange(3):
      output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG7'], test_name,
                           self.cjt)
      try:
        self.assertTrue(output['success'])
      except AssertionError:
        notes = 'Error printing %s' % Constants.IMAGES['PNG7']
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise

    print 'Verify all 3 job printed correctly.'
    print 'If all 3 Print Test pages are not printed, fail this test.'
    self.ManualPass(test_id, test_name)

  def testPrintToOfflinePrinter(self):
    """Validate offline printer prints all queued jobs when back online."""
    test_id = '83869333-ff32-4093-a557-323887204902'
    test_name = 'testPrintToOfflinePrinter'

    print 'This tests that an offline printer will print all jobs'
    print 'when it comes back online.'
    PromptAndWaitForUserAction('Press ENTER once printer is powered off')

    for _ in xrange(3):
      print 'Submitting job #',_,' to the print queue.'
      output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PNG7'], test_name,
                           self.cjt)
      try:
        self.assertTrue(output['success'])
      except AssertionError:
        notes = 'Error printing %s' % Constants.IMAGES['PNG7']
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      try:
        _gcp.WaitJobStateIn(output['job']['id'],
                            _device.dev_id,
                            GCPConstants.QUEUED)
      except AssertionError:
        notes = 'Print job %s is not in Queued state.' %(_)
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise

    PromptUserAction('Power on the printer and wait...')
    service = Wait_for_privet_mdns_service(300, Constants.PRINTER['NAME'],
                                           _logger)
    try:
      self.assertIsNotNone(service)
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
    test_id = '01808d62-7c0f-4427-90ce-29f429f1d594'
    test_name = 'testDeleteQueuedJob'

    PromptAndWaitForUserAction('Press ENTER once printer is powered off')

    doc_to_print = Constants.IMAGES['PNG7']

    print 'Attempting to add a job to the queue.'
    output = _gcp.Submit(_device.dev_id, doc_to_print, test_name, self.cjt)

    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing %s' % doc_to_print
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    try:
      _gcp.WaitJobStateIn(output['job']['id'],
                          _device.dev_id,
                          GCPConstants.QUEUED)
    except AssertionError:
      notes = 'Print job is not in queued state.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    print 'Attempting to delete job in queued state.'
    job_delete = _gcp.DeleteJob(output['job']['id'])
    try:
      self.assertTrue(job_delete['success'])
    except AssertionError:
      notes = 'Queued job not deleted.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      PromptUserAction('Power on the printer and wait...')
      service = Wait_for_privet_mdns_service(300, Constants.PRINTER['NAME'],
                                             _logger)
      try:
        self.assertIsNotNone(service)
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
    test_id = '80877c2a-f46e-4256-80d9-474ff16eb60b'
    test_name = 'testErrorRecovery'

    print 'Submitting a malformatted PDF file.'

    # First printing a malformatted PDF file. Not expected to print.
    _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF5'], 'Malformat', self.cjt)
    # Now print a valid file.
    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF9'], test_name,
                         self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Job did not print after malformatted print job.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        _gcp.WaitJobStateIn(output['job']['id'],
                            _device.dev_id,
                            GCPConstants.DONE,
                            timeout=Constants.TIMEOUT['PRINTING'])
      except AssertionError:
        notes = ('Job state did not transition to %s within %s seconds.' %
                 (GCPConstants.DONE, Constants.TIMEOUT['PRINTING']))
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        print 'Verify malformatted file did not put printer in error state.'
        print 'Verify print test page printed correctly.'
        self.ManualPass(test_id, test_name)

  def testPagesPrinted(self):
    """Verify printer properly reports number of pages printed."""
    test_id = 'bfd7e2d8-e75a-4a7b-8f47-00d0c1081963'
    test_name = 'testPagesPrinted'

    output = _gcp.Submit(_device.dev_id, Constants.IMAGES['PDF10'], test_name,
                         self.cjt)
    print 'Printing a 3 page PDF file'
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing 3 page PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      try:
        job = _gcp.WaitJobStateIn(output['job']['id'],
                                  _device.dev_id,
                                  GCPConstants.DONE,
                                  timeout=Constants.TIMEOUT['PRINTING'])
      except AssertionError:
        notes = ('Job state did not transition to %s within %s seconds.' %
                 (GCPConstants.DONE, Constants.TIMEOUT['PRINTING']))
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
    _device.assertPrinterIsRegistered()

    _logger.info('Sleeping for 1 day before running additional tests.')
    print 'Sleeping for 1 day before running additional tests.'
    Sleep('ONE_DAY')

  def testPrinterOnline(self):
    """validate printer has online status."""
    test_id = '490821e9-99b8-4f2b-a54c-6e4cfcb6f45c'
    test_name = 'testPrinterOnline'

    # Tokens have expired since the 24 hr sleep, refresh them
    _oauth2.RefreshToken()
    _device.auth_token = Constants.AUTH['ACCESS']
    _gcp.auth_token = Constants.AUTH['ACCESS']

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
    LogoCert.setUpClass(cls)
    _device.assertPrinterIsRegistered()
    LogoCert.GetDeviceDetails()

  def testUnregisterDevice(self):
    """Unregister printer."""
    test_id = 'd008a124-fb56-40de-a530-7c510f1fe078'
    test_name = 'testUnregisterDevice'

    test_id2 = 'b112a9bc-4a11-4956-893c-4498ff753058'
    test_name2 = 'testUnregisteredDevicePrivetAdvertise'

    test_id3 = '8e158286-674f-486c-9a61-be2c61de20b9'
    test_name3 = 'testOffDeviceIsDeleted'

    print 'Printer needs to be registered to begin this testcase'
    is_registered = _device.isPrinterRegistered()
    try:
      self.assertTrue(is_registered)
    except AssertionError:
      notes = 'Printer needs to be registered before this testcase runs'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    PromptAndWaitForUserAction('Press ENTER once printer is powered off')
    success = _device.UnRegister(_device.auth_token)
    try:
      self.assertTrue(success)
    except AssertionError:
      notes = 'Error deleting registered printer. GCP delete API call failed'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      notes = 'GCP delete API returned success.'
      self.LogTest(test_id, test_name, 'Passed', notes)

    PromptUserAction('Power on the printer and wait...')
    print ('Wait up to 2 minutes for the printer to advertise as '
           'an unregistered device')
    success = waitForAdvertisementRegStatus(Constants.PRINTER['NAME'],
                                            False, 120)
    try:
      self.assertTrue(success)
    except AssertionError:
      notes = ('Deleted device not found advertising or found advertising as '
               'registered')
      self.LogTest(test_id2, test_name2, 'Failed', notes)
    else:
      notes = 'Deleted device found advertising as unregistered device.'
      self.LogTest(test_id2, test_name2, 'Passed', notes)

    res = _gcp.Search(_device.name)
    try:
      self.assertFalse(res['printers'])
    except AssertionError:
      notes = 'Unregistered printer found via the GCP Search API.'
      self.LogTest(test_id3, test_name3, 'Failed', notes)
      raise
    else:
      notes = ('Unregistered printer not found via the GCP Search API')
      self.LogTest(test_id3, test_name3, 'Passed', notes)

class PostUnregistration(LogoCert):
  """Test local printing on an unregistered device
     This test is put at the end instead of inside PreRegistration()
     because the PWG file used for printing is generated from GCP which requires
     the printer to be registered
  """

  @classmethod
  def setUpClass(cls):
    LogoCert.setUpClass(cls)
    _device.assertPrinterIsUnregistered()


  def testLocalPrintGuestUserUnregisteredPrinter(self):
    """Verify local print for unregistered printer is correct."""
    test_id = '379dcb9a-2287-41bc-a387-be0d8a132c25'
    test_name = 'testLocalPrintGuestUserUnregisteredPrinter'

    if not Constants.CAPS['LOCAL_PRINT']:
      notes = 'Printer does not support unregistered local printing.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return

    if not os.path.exists(Constants.IMAGES['PWG1']):
      print '%s not found.' % (Constants.IMAGES['PWG1'])
      print 'LocalPrinting suite should be run before this suite'
      print 'LocalPrinting will produce the raster file needed for this test'
      notes = 'Run LocalPrinting suite before PostUnregistration suite'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise

    # New instance of device that is not authenticated - contains no auth-token
    guest_device = Device(_logger, None, None, privet_port=_device.port)
    guest_device.GetDeviceCDDLocally()

    cjt = CloudJobTicket(guest_device.privet_info['version'])

    job_id = guest_device.LocalPrint(test_name, Constants.IMAGES['PWG1'], cjt,
                                     'image/pwg-raster')
    try:
      self.assertIsNotNone(job_id)
    except AssertionError:
      notes = ('Guest failed to print a page via local printing '
               'on the unregistered printer.')
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      print ('Guest successfully printed a page via local printing '
             'on the unregistered printer.')
      print 'If not, fail this test.'
      self.ManualPass(test_id, test_name)

class CloudPrinting(LogoCert):
  """Test printing using Cloud Print."""

  # class level variable for tracking token refreshes
  _prev_token_time = None

  def submit(self, dev_id, content, test_id, test_name, cjt, is_url=False):
    """Wrapper for submitting a print job to the printer for logging purposes

    Args:
      dev_id: string, target printer to print from.
      content: string, url or absolute filepath of the item to print.
      test_id: string, id of the testcase
      test_name: string, title of the print job.
      cjt: CloudJobTicket, object that defines the options of the print job
      is_url: boolean, flag to identify between url's and files
    Returns:
      dictionary, response msg from the GCP server if successful;
                  otherwise, raise an exception
    """
    try:
      output = _gcp.Submit(dev_id, content, test_name, cjt, is_url)
      return output
    except AssertionError:
      notes = 'Submit API failed'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise


  def setUp(self):
    # Create a fresh CJT for each test case
    self.cjt = CloudJobTicket(_device.details['gcpVersion'])

    # Refresh tokens if it's been more than 30 minutes (1800 seconds)
    # If Access tokens expire, GCP calls will fail
    if time.time() > CloudPrinting._prev_token_time + 1800:
      _oauth2.RefreshToken()
      _device.auth_token = Constants.AUTH['ACCESS']
      _gcp.auth_token = Constants.AUTH['ACCESS']
      CloudPrinting._prev_token_time = time.time()


  def waitForCloudPrintJobCompletion(self, test_id, test_name, output):
    """Wait for cloudprint job to complete within configured time.

    If job does not complete within configured time, log the error and
    raise an exception.

    Args:
      test_id: string, id of the testcase
      test_name: string, title of the print job
      output: dictionary, submit response from GCP server
    """
    print '[Configurable timeout] PRINTING'
    try:
      _gcp.WaitJobStateIn(output['job']['id'],
                          _device.dev_id,
                          GCPConstants.DONE,
                          timeout=Constants.TIMEOUT['PRINTING'])
    except AssertionError:
      notes = ('Job state did not transition to %s within %s seconds.' %
               (GCPConstants.DONE, Constants.TIMEOUT['PRINTING']))
      self.LogTest(test_id, test_name, 'Failed', notes)
      print ('ERROR: Either TIMEOUT[PRINTING] is too small in _config.py or '
             'Job is in error state.')
      print 'Check the GCP management page to see if it is the latter.'
      PromptAndWaitForUserAction('Press ENTER when problem is resolved to '
                                 'continue testing.')
      raise


  def waitAndManualPass(self, test_id, test_name, output,
                        verification_prompt=None):
    """Wait for cloudprint job completion then prompt for manual verification.

    Args:
      test_id: string, id of the testcase
      test_name: string, title of the print job
      output: dictionary, submit response from GCP server
      verification_prompt: string, manual verification prompt message
    """
    self.waitForCloudPrintJobCompletion(test_id, test_name, output)

    if verification_prompt:
      print verification_prompt
    self.ManualPass(test_id, test_name)


  @classmethod
  def setUpClass(cls):
    cls._prev_token_time = time.time()
    LogoCert.setUpClass(cls)
    LogoCert.GetDeviceDetails()

  def test_01_CloudPrintMediaSizeSelect(self):
    """Verify cloud printing with media size option."""
    test_id = 'c8de872f-49bd-45b7-9623-8db0861aed35'
    test_name = 'testPrintMediaSizeSelect'
    _logger.info('Testing the selection of A4 media size.')
    PromptAndWaitForUserAction('Load printer with A4 size paper. '
                               'Select return when ready.')

    self.cjt.AddSizeOption(GCPConstants.A4_HEIGHT, GCPConstants.A4_WIDTH)
    output = self.submit(_device.dev_id, Constants.IMAGES['PNG1'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error selecting A4 media size.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)
    finally:
      PromptAndWaitForUserAction('Load printer with letter size paper. '
                                 'Select return when ready.')

  def test_02_CloudPrintPageOrientation(self):
    """Verify cloud printing with media size option."""
    test_id = '5085e650-5f08-43a5-bb61-8a485a8122e9'
    test_name = 'testPageOrientation'
    _logger.info('Testing the selection of non-default orientation')

    self.cjt.AddPageOrientationOption(GCPConstants.LANDSCAPE)
    output = self.submit(_device.dev_id, Constants.IMAGES['PDF4'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing in the non-default orientation.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_03_CloudPrintJpgDpiSetting(self):
    """Verify cloud printing a jpg with DPI option."""
    test_id = 'aed7d8a4-e669-4a07-b47a-d833d1ef6b16'
    test_name = 'testPrintJpgDpiSetting'

    dpi_options = _device.cdd['caps']['dpi']['option']

    for dpi_option in dpi_options:
      _logger.info('Setting dpi to %s', dpi_option)

      self.cjt.AddDpiOption(dpi_option['horizontal_dpi'],
                            dpi_option['vertical_dpi'])
      output = self.submit(_device.dev_id, Constants.IMAGES['PNG8'], test_id,
                           test_name, self.cjt)
      try:
        self.assertTrue(output['success'])
      except AssertionError:
        notes = 'Error printing with dpi set to %s' % dpi_option
        self.LogTest(test_id, test_name, 'Failed', notes)
        raise
      else:
        self.waitForCloudPrintJobCompletion(test_id, test_name, output)
    self.ManualPass(test_id, test_name)


  def test_04_CloudPrintJpg2Copies(self):
    """Verify cloud printing Jpg with copies option set to 2."""
    test_id = '96d913fc-35cb-48ae-9e73-1737a36ae02a'
    test_name = 'testPrintJpg2Copies'
    if not Constants.CAPS['COPIES_CLOUD']:
      notes = 'Copies not supported.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    _logger.info('Setting copies to 2...')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddCopiesOption(2)
    output = self.submit(_device.dev_id, Constants.IMAGES['JPG12'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing with copies = 2.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_05_CloudPrintPdfDuplexLongEdge(self):
    """Verify cloud printing a pdf with the duplex option set to long edge."""
    test_id = '068e4390-0e88-4632-a2d4-83dad3b36d09'
    test_name = 'testPrintPdfDuplexLongEdge'
    if not Constants.CAPS['DUPLEX']:
      notes = 'Duplex not supported.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    _logger.info('Setting duplex to long edge...')

    self.cjt.AddDuplexOption(GCPConstants.LONG_EDGE)
    output = self.submit(_device.dev_id, Constants.IMAGES['PDF10'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing in duplex long edge.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_06_CloudPrintPdfDuplexShortEdge(self):
    """Verify cloud printing a pdf with the duplex option set to short edge."""
    test_id = '2b9eb721-48ee-46c5-bf76-6f0868a6acbf'
    test_name = 'testPrintPdfDuplexShortEdge'
    if not Constants.CAPS['DUPLEX']:
      notes = 'Duplex not supported.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    _logger.info('Setting duplex to short edge...')

    self.cjt.AddDuplexOption(GCPConstants.SHORT_EDGE)
    output = self.submit(_device.dev_id, Constants.IMAGES['PDF10'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing in duplex short edge.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_07_CloudPrintColorSelect(self):
    """Verify cloud printing with color options."""
    test_id = '1c433239-bec8-45a6-b1c1-d4190e4cc085'
    test_name = 'testPrintColorSelect'
    if not Constants.CAPS['COLOR']:
      notes = 'Color is not supported.'
      self.LogTest(test_id, test_name, 'Skipped', notes)
      return
    _logger.info('Printing with color selected.')

    self.cjt.AddColorOption(self.color)
    output = self.submit(_device.dev_id, Constants.IMAGES['PDF13'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing color PDF with color selected.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)

  def test_08_CloudPrintPdfReverseOrder(self):
    """Verify cloud printing a pdf with reverse order option."""
    test_id = 'f7551021-cb3c-4a00-93e4-1ef619d5e15c'
    test_name = 'testPrintPdfReverseOrder'
    _logger.info('Print with reverse order flag set...')

    self.cjt.AddReverseOption()
    output = self.submit(_device.dev_id, Constants.IMAGES['PDF10'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing in reverse order.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)

  def test_09_CloudPrintPdfPageRangePage2(self):
    """Verify cloud printing a pdf with the page range option set to 2."""
    test_id = 'bf37a319-321d-4b50-9e5a-44b542dacc50'
    test_name = 'testPrintPdfPageRangePage2'
    _logger.info('Setting page range to page 2 only')

    self.cjt.AddPageRangeOption(2, end=2)
    output = self.submit(_device.dev_id, Constants.IMAGES['PDF1'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing with page range set to page 2 only.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_10_CloudPrintPngFillPage(self):
    """Verify cloud printing a png with the fill page option."""
    test_id = 'ad1eff9e-6516-46c1-8ff9-c9de845c3e4c'
    test_name = 'testPrintPngFillPage'
    _logger.info('Setting print option to Fill Page...')

    self.cjt.AddFitToPageOption(GCPConstants.FILL)
    output = self.submit(_device.dev_id, Constants.IMAGES['PNG3'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing with Fill Page option.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_11_CloudPrintPngFitToPage(self):
    """Verify cloud printing a png with the fit to page option."""
    test_id = '58913ffe-93c3-4405-81ac-ec592169b8a7'
    test_name = 'testPrintPngFitToPage'
    _logger.info('Setting print option to Fit to Page...')

    self.cjt.AddFitToPageOption(GCPConstants.FIT)
    output = self.submit(_device.dev_id, Constants.IMAGES['PNG3'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing with Fit to Page option.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_12_CloudPrintPngGrowToPage(self):
    """Verify cloud printing a png with the grow to page option."""
    test_id = 'c189611b-12f0-4a2e-ba9f-3672c89206d6'
    test_name = 'testPrintPngGrowToPage'
    _logger.info('Setting print option to Grow to Page...')

    self.cjt.AddFitToPageOption(GCPConstants.GROW)
    output = self.submit(_device.dev_id, Constants.IMAGES['PNG3'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing with Grow To Page option.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_13_CloudPrintPngShrinkToPage(self):
    """Verify cloud printing a png with the shrink to page option."""
    test_id = '00b50f0a-a196-4c4a-823c-de9547010735'
    test_name = 'testPrintPngShrinkToPage'
    _logger.info('Setting print option to Shrink to Page...')

    self.cjt.AddFitToPageOption(GCPConstants.SHRINK)
    output = self.submit(_device.dev_id, Constants.IMAGES['PNG3'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing with Shrink To Page option.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_14_CloudPrintPngNoFitting(self):
    """Verify cloud printing a png with the no fitting option."""
    test_id = 'b2ed2f00-e449-4805-995e-8dac5fde7ab2'
    test_name = 'testPrintPngNoFitting'
    _logger.info('Setting print option to No Fitting...')

    self.cjt.AddFitToPageOption(GCPConstants.NO_FIT)
    output = self.submit(_device.dev_id, Constants.IMAGES['PNG3'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing with No Fitting option.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_15_CloudPrintJpgPortrait(self):
    """Verify cloud printing a jpg with the portrait option."""
    test_id = '951209b8-c615-4c5b-864b-cdbfbe80c195'
    test_name = 'testPrintJpgPortrait'
    _logger.info('Print simple JPG file with portrait orientation.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(GCPConstants.PORTRAIT)
    output = self.submit(_device.dev_id, Constants.IMAGES['JPG14'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing JPG file in portrait orientation.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_16_CloudPrintJpgLandscape(self):
    """Verify cloud printing a jpg with the landscape option."""
    test_id = '007d7987-c496-45b7-a43b-4ca58625e124'
    test_name = 'testPrintJpgLandscape'
    _logger.info('Print simple JPG file with landscape orientation.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(GCPConstants.LANDSCAPE)
    output = self.submit(_device.dev_id, Constants.IMAGES['JPG7'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing JPG file with landscape orientation.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_17_CloudPrintJpgBlacknWhite(self):
    """Verify cloud printing a jpg with the monochrome option."""
    test_id = 'e725888b-1e3c-45d7-963a-19f13296c57e'
    test_name = 'testPrintJpgBlacknWhite'
    _logger.info('Print black and white JPG file.')

    self.cjt.AddColorOption(self.monochrome)
    output = self.submit(_device.dev_id, Constants.IMAGES['JPG1'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing black and white JPG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_18_CloudPrintJpgMultiImageWithText(self):
    """Verify cloud printing a multi-image jpg in landscape."""
    test_id = 'b842c6a0-eff1-4070-adbd-33a0352fad81'
    test_name = 'testPrintJpgMultiImageWithText'
    _logger.info('Print multi image with text JPG file.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(GCPConstants.LANDSCAPE)
    output = self.submit(_device.dev_id, Constants.IMAGES['JPG9'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing multi-image with text JPG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_19_CloudPrintJpgStepChartLandscape(self):
    """Verify cloud printing a step-chart jpg with the landscape option."""
    test_id = '6a77f2b3-d752-4300-9ba6-7a3fe7132556'
    test_name = 'testPrintJpgStepChartLandscape'
    _logger.info('Print step chart JPG file in landscape orientation.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(GCPConstants.LANDSCAPE)
    output = self.submit(_device.dev_id, Constants.IMAGES['JPG13'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing step chart JPG file in landscape.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_20_CloudPrintJpgLarge(self):
    """Verify cloud printing a large jpg with the landscape option."""
    test_id = 'fe34f8a5-9e95-4b39-bdba-25c782d7ad09'
    test_name = 'testPrintJpgLarge'
    _logger.info('Print large JPG file with landscape orientation.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(GCPConstants.LANDSCAPE)
    output = self.submit(_device.dev_id, Constants.IMAGES['JPG3'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing large JPG file in landscape.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_21_CloudPrintFilePdf(self):
    """Test cloud printing a standard, 1 page b&w PDF file."""
    test_id = '289773db-af6f-4303-a859-53dce219f07e'
    test_name = 'testPrintFilePdf'
    _logger.info('Printing a black and white 1 page PDF file.')

    self.cjt.AddColorOption(self.monochrome)
    output = self.submit(_device.dev_id, Constants.IMAGES['PDF4'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing 1 page, black and white PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_22_CloudPrintFileMultiPagePdf(self):
    """Test cloud printing a standard, 3 page color PDF file."""
    test_id = '2beca3f9-6a43-4272-a049-613153da4de7'
    test_name = 'testPrintFileMultiPagePdf'
    _logger.info('Printing a 3 page, color PDF file.')

    self.cjt.AddColorOption(self.color)
    output = self.submit(_device.dev_id, Constants.IMAGES['PDF10'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing 3 page, color PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_23_CloudPrintFileLargeColorPdf(self):
    """Test cloud printing a 20 page, color PDF file."""
    test_id = 'bdd50e2d-513d-4a48-a9c1-388a88f0b7ad'
    test_name = 'testPrintFileLargeColorPdf'
    _logger.info('Printing a 20 page, color PDF file.')

    self.cjt.AddColorOption(self.color)
    output = self.submit(_device.dev_id, Constants.IMAGES['PDF1'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing 20 page, color PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_24_CloudPrintFilePdfV1_2(self):
    """Test cloud printing PDF version 1.2 file."""
    test_id = '7ab294f5-31b1-48ee-9c5a-cd77dc7cfaf3'
    test_name = 'testPrintFilePdfV1_2'
    _logger.info('Printing a PDF v1.2 file.')

    output = self.submit(_device.dev_id, Constants.IMAGES['PDF1.2'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing PDF v1.2 file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_25_CloudPrintFilePdfV1_3(self):
    """Test cloud printing PDF version 1.3 file."""
    test_id = 'f95b8ec9-48c7-46c5-b233-50cf410a8f04'
    test_name = 'testPrintFilePdfV1_3'
    _logger.info('Printing a PDF v1.3 file.')

    output = self.submit(_device.dev_id, Constants.IMAGES['PDF1.3'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing PDF v1.3 file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_26_CloudPrintFilePdfV1_4(self):
    """Test cloud printing PDF version 1.4 file."""
    test_id = '45da57b3-f5b9-4b6e-a40e-79ff2bd8d451'
    test_name = 'testPrintFilePdfV1_4'
    _logger.info('Printing a PDF v1.4 file.')

    output = self.submit(_device.dev_id, Constants.IMAGES['PDF1.4'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing PDF v1.4 file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_27_CloudPrintFilePdfV1_5(self):
    """Test cloud printing PDF version 1.5 file."""
    test_id = 'e4a8a756-1ebb-47d4-9b83-17d6b0973883'
    test_name = 'testPrintFilePdfV1_5'
    _logger.info('Printing a PDF v1.5 file.')

    output = self.submit(_device.dev_id, Constants.IMAGES['PDF1.5'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing PDF v1.5 file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_28_CloudPrintFilePdfV1_6(self):
    """Test cloud printing PDF version 1.6 file."""
    test_id = '7a35cf71-9b92-4bb8-aaf7-277d196ca42c'
    test_name = 'testPrintFilePdfV1_6'
    _logger.info('Printing a PDF v1.6 file.')

    output = self.submit(_device.dev_id, Constants.IMAGES['PDF1.6'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing PDF v1.6 file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_29_CloudPrintFilePdfV1_7(self):
    """Test cloud printing PDF version 1.7 file."""
    test_id = 'cc58720f-ed23-4506-8a9d-c852a71ba1cb'
    test_name = 'testPrintFilePdfV1_7'
    _logger.info('Printing a PDF v1.7 file.')

    output = self.submit(_device.dev_id, Constants.IMAGES['PDF1.7'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing PDF v1.7 file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_30_CloudPrintFilePdfColorTicket(self):
    """Test cloud printing PDF file of Color Ticket in landscape orientation."""
    test_id = '286cc889-88c3-4bc8-87e5-cc44c921f52d'
    test_name = 'testPrintFilePdfColorTicket'
    _logger.info('Printing PDF Color ticket in with landscape orientation.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(GCPConstants.LANDSCAPE)
    output = self.submit(_device.dev_id, Constants.IMAGES['PDF2'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing color boarding ticket PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_31_CloudPrintFilePdfLetterMarginTest(self):
    """Test cloud printing PDF Letter size margin test file."""
    test_id = '361ae296-321d-4b6b-b84c-a2d60fb40d99'
    test_name = 'testPrintFilePdfLetterMarginTest'
    _logger.info('Printing PDF Letter Margin Test.')

    output = self.submit(_device.dev_id, Constants.IMAGES['PDF3'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing letter margin test PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_32_CloudPrintFilePdfSimpleLandscape(self):
    """Test cloud printing PDF with landscape layout."""
    test_id = 'c4ed07f4-c32e-42b0-8a7d-4dae2cd2ec7b'
    test_name = 'testPrintFilePdfSimpleLandscape'
    _logger.info('Printing simple PDF file in landscape.')

    self.cjt.AddPageOrientationOption(GCPConstants.LANDSCAPE)
    output = self.submit(_device.dev_id, Constants.IMAGES['PDF8'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing simple PDF file in landscape.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_33_CloudPrintFilePdfColorTest(self):
    """Test cloud printing PDF Color Test file."""
    test_id = '28286e1d-3b81-46b4-8372-1f97f88e5a58'
    test_name = 'testPrintFilePdfColorTest'
    _logger.info('Printing PDF Color Test page.')

    self.cjt.AddColorOption(self.color)
    output = self.submit(_device.dev_id, Constants.IMAGES['PDF11'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing Color Test PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_34_CloudPrintFilePdfComplexTicket(self):
    """Test cloud printing complex ticket PDF file."""
    test_id = 'afb758a1-4a6a-40a6-92fa-005bbd9addaa'
    test_name = 'testPrintFilePdfComplexTicket'
    _logger.info('Printing PDF of complex ticket.')

    self.cjt.AddColorOption(self.color)
    output = self.submit(_device.dev_id, Constants.IMAGES['PDF14'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing complex ticket that is PDF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_35_CloudPrintFileSmallGIF(self):
    """Test cloud printing a small GIF file."""
    test_id = 'd23d2310-91ab-4d62-ad21-fef3675be6c7'
    test_name = 'testPrintFileSmallGIF'
    _logger.info('Printing small GIF file.')

    self.cjt.AddColorOption(self.color)
    output = self.submit(_device.dev_id, Constants.IMAGES['GIF4'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing small GIF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_36_CloudPrintFileLargeGIF(self):
    """Test cloud printing a large GIF file."""
    test_id = '3f9e7136-24bd-4007-84b0-216093bcad7b'
    test_name = 'testPrintFileLargeGIF'
    _logger.info('Printing large GIF file.')

    self.cjt.AddColorOption(self.color)
    output = self.submit(_device.dev_id, Constants.IMAGES['GIF1'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing large GIF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_37_CloudPrintFileBlackNWhiteGIF(self):
    """Test cloud printing a black & white GIF file."""
    test_id = '96b6f311-82e7-4eb0-817b-d50dd7a4b1ef'
    test_name = 'testPrintFileBlackNWhiteGIF'
    _logger.info('Printing black and white GIF file.')

    self.cjt.AddColorOption(self.monochrome)
    output = self.submit(_device.dev_id, Constants.IMAGES['GIF3'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing black and white GIF file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_38_CloudPrintFileHTML(self):
    """Test cloud printing HTML file."""
    test_id = 'ab13f135-4c39-4c9f-9352-6ae9bf2c1664'
    test_name = 'testPrintFileHTML'
    _logger.info('Printing HTML file.')

    output = self.submit(_device.dev_id, Constants.IMAGES['HTML1'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing HTML file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_39_CloudPrintFilePngPortrait(self):
    """Test cloud printing PNG portrait file."""
    test_id = '528a5015-317f-4f85-a80c-10da77c22fe2'
    test_name = 'testPrintFilePngPortrait'
    _logger.info('Printing PNG portrait file.')

    self.cjt.AddColorOption(self.color)
    output = self.submit(_device.dev_id, Constants.IMAGES['PNG8'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing PNG portrait file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_40_CloudPrintFileColorPngLandscape(self):
    """Test cloud printing color PNG file."""
    test_id = 'd9bdc76d-a27e-4d6b-8a72-43ec0c8ad881'
    test_name = 'testPrintFileColorPngLandscape'
    _logger.info('Printing Color PNG file in landscape.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(GCPConstants.LANDSCAPE)
    output = self.submit(_device.dev_id, Constants.IMAGES['PNG2'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing Color PNG in landscape.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_41_CloudPrintFilePngWithLetters(self):
    """Test cloud printing PNG containing letters."""
    test_id = 'd5e07594-f141-40b6-90fb-3e0268168936'
    test_name = 'testPrintFilePngWithLetters'
    _logger.info('Printing PNG file with letters.')

    self.cjt.AddColorOption(self.color)
    self.cjt.AddPageOrientationOption(GCPConstants.LANDSCAPE)
    output = self.submit(_device.dev_id, Constants.IMAGES['PNG4'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing PNG file containing letters.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_42_CloudPrintFilePngColorImageWithText(self):
    """Test cloud printing color images with text PNG file."""
    test_id = '7d9e30c2-52c2-4780-a2c4-64778ff31b36'
    test_name = 'testPrintFilePngColorImageWithText'
    _logger.info('Printing color images with text PNG file.')

    self.cjt.AddColorOption(self.color)
    output = self.submit(_device.dev_id, Constants.IMAGES['PNG6'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing color images with text PNG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_43_CloudPrintFileLargePng(self):
    """Test cloud printing Large PNG file."""
    test_id = 'b64c37cd-3ba8-4dfc-bb3b-652e1ce0e08d'
    test_name = 'testPrintFileLargePng'
    _logger.info('Printing large PNG file.')

    self.cjt.AddColorOption(self.color)
    output = self.submit(_device.dev_id, Constants.IMAGES['PNG9'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing large PNG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_44_CloudPrintFileSvgSimple(self):
    """Test cloud printing simple SVG file."""
    test_id = 'eb8c1076-c19d-442f-adcc-50909e1a0d73'
    test_name = 'testPrintFileSvgSimple'
    _logger.info('Printing simple SVG file.')

    output = self.submit(_device.dev_id, Constants.IMAGES['SVG2'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing simple SVG file.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_45_CloudPrintFileSvgWithImages(self):
    """Test cloud printing SVG file with images."""
    test_id = 'a130cd96-edce-4359-8cc9-3702c8a6e3f4'
    test_name = 'testPrintFileSvgWithImages'
    _logger.info('Printing SVG file with images.')

    self.cjt.AddColorOption(self.color)
    output = self.submit(_device.dev_id, Constants.IMAGES['SVG1'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing SVG file with images.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_46_CloudPrintFileTiffRegLink(self):
    """Test cloud printing TIFF file of GCP registration link."""
    test_id = 'f82f3e7b-5acd-4aa2-8d72-d4c94b60fae7'
    test_name = 'testPrintFileTiffRegLink'
    _logger.info('Printing TIFF file of GCP registration link.')

    output = self.submit(_device.dev_id, Constants.IMAGES['TIFF1'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing TIFF file of GCP registration link.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)


  def test_47_CloudPrintFileTiffPhoto(self):
    """Test cloud printing TIFF file of photo."""
    test_id = '0bcd79a1-b850-417e-ad42-5a525d358091'
    test_name = 'testPrintFileTiffPhoto'
    _logger.info('Printing TIFF file of photo.')

    self.cjt.AddColorOption(self.color)
    output = self.submit(_device.dev_id, Constants.IMAGES['TIFF2'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing TIFF file of photo.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitAndManualPass(test_id, test_name, output)

  def test_48_CloudPrintMarginsOptions(self):
    """Test cloud printing with margins option."""
    test_id = 'e82ef19a-f744-4ab6-a0aa-c74763907bf0'
    test_name = 'testPrintMarginsOptions'

    if not Constants.CAPS['MARGIN']:
      self.LogTest(test_id, test_name, 'Skipped', 'No Margin support')
      return

    self.cjt.AddMarginOption(0, 0, 0, 0)
    output = self.submit(_device.dev_id, Constants.IMAGES['PDF9'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error printing with margins set to 0.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      self.waitForCloudPrintJobCompletion(test_id, test_name, output)

    self.cjt.AddMarginOption(50000, 50000, 50000, 50000)
    output = self.submit(_device.dev_id, Constants.IMAGES['PDF9'], test_id,
                         test_name, self.cjt)
    try:
      self.assertTrue(output['success'])
    except AssertionError:
      notes = 'Error local printing with margins set to 5cm.'
      self.LogTest(test_id, test_name, 'Failed', notes)
      raise
    else:
      prompt = 'The 1st print job should have no margins.\n'
      prompt += 'The 2nd print job should have 5cm margins for all sides.\n'
      prompt += 'If the margins are not correct, fail this test.'
      self.waitAndManualPass(test_id, test_name, output,
                             verification_prompt=prompt)


if __name__ == '__main__':
  runner = unittest.TextTestRunner(verbosity=2)
  suite = unittest.TestSuite()

  for testsuite in Constants.TEST['RUN']:
    if testsuite.startswith('#'):
      continue
    print 'Adding %s to list of suites to run' % (testsuite)
    suite.addTest(unittest.makeSuite(globals()[testsuite]))

  runner.run(suite)
