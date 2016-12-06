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


Package wide constants and variables used by the Logo Cert pacakge.

Use this module to support need constants and variables across multiple
modules or classes. There are also some common functions defined here.
"""

import mimetools
import os


class Constants(object):
  """A classs that holds constants for the Logo Certification tool."""

  ACCOUNTS = 'https://accounts.google.com'

  AUTH = {
      'CRED_FILE': 'credentials.txt',
      'REDIRECT': 'urn:ietf:wg:oauth:2.0:oob',
      'SCOPE': ('https://www.googleapis.com/auth/cloudprint '
                'https://spreadsheets.google.com/feeds/'),
      'USER_AGENT': 'CloudPrint_Client',
      }

  # AUTOMODE determines if manual input is needed for some test results.
  # If a user must examine a print job to determine pass or fail, set
  # AUTOMODE to False.
  AUTOMODE = False

  # A simple marker for the boundary of a multipart field for form data.
  BOUNDARY = mimetools.choose_boundary()

  # CAPS represent device features and affects which tests will be run.
  # The values should be True or False.
  CAPS = {
      'COLLATE': False,
      'COLOR': False,
      'COPIES_LOCAL': True,  # If a Printer supports copies for local printing,
                             # set this to True.
      'COPIES_CLOUD': True,  # If a Printer supports copies for cloud printing,
                             # set this to True.
      'COVER': True,         # Not all printers have a cover.
      'DUPLEX': True,
      'LAYOUT_ISSUE': True,  # Printer must set page orientation for local
                             # printing, so page_orientation is still needed
                             # in the printer capabilities.
      'LOCAL_PRINT': True,   # If a Printer supports local printing without
                             # being registered, set this to True.
      'TONER': True,  # Set to false if printer is thermal or has no toner.
      'TRAY_SENSOR': False,  # Set this to True if printer has sensor to detect
                             # if the paper tray is open.
      'MEDIA_SENSOR': False, # Set this to True if printer has sensor to detect
                             # if the paper tray is empty.
      'MARGIN': True,		 # If a Printer supports Margin specifications, 
						     # set this to True
      }

  # Sleep contains the various durations of time.sleep() in SECONDS that are used in this suite of scripts
  SLEEP = {
    'POLL' : 1,               # Used inside loops to space out polls to GCP/Privet API's
    'REGISTRATION': 5,        # Printer dependent: used after user accepts or cancels registration request
                              #                    on the printer
    'PRINTER_STATE': 10,      # Printer dependent: used when printer state is altered physically
                              #                    e.g. Paper tray open/close, ink catridge remove/replaced
    'ONE_DAY': 86400,         # 24 hrs in seconds
    'AUTO_RUN': 5             # Used if AUTOMODE is set to be true

  }
  # Carriage return.
  CRLF = '\r\n'

  GCP = {
      'LEARN': 'http://www.google.com/cloudprint/learn/',
      'MGT': 'https://www.google.com/cloudprint',
      'PRINTERS': 'https://www.google.com/cloudprint#printers',
      'SIMULATE': 'https://www.google.com/cloudprint/simulate.html',
      }

  GOOGLE = 'https://www.google.com'


  image_dir = os.path.join(os.getcwd(), 'images')
  IMAGES = {
      'GIF1': os.path.join(image_dir, '6MB.gif'),
      'GIF2': os.path.join(image_dir, 'img_0012.gif'),
      'GIF3': os.path.join(image_dir, 'poster.gif'),
      'GIF4': os.path.join(image_dir, 'Google-Glass.gif'),
      'HTML1': os.path.join(image_dir, 'ChromeOSPowerManagementSpec.html'),
      'JPG1': os.path.join(image_dir, 'b&w-test.jpg'),
      'JPG2': os.path.join(image_dir, 'colorkey.jpg'),
      'JPG3': os.path.join(image_dir, 'GoogleArt.jpg'),
      'JPG4': os.path.join(image_dir, 'GoogleCampus.jpg'),
      'JPG5': os.path.join(image_dir, 'google-car.jpg'),
      'JPG6': os.path.join(image_dir, 'GoogleGlass.jpg'),
      'JPG7': os.path.join(image_dir, 'GoogleGlass2.jpg'),
      'JPG8': os.path.join(image_dir, 'landscape-test.jpg'),
      'JPG9': os.path.join(image_dir, 'largeref.jpg'),
      'JPG10': os.path.join(image_dir, 'max_test_big.jpg'),
      'JPG11': os.path.join(image_dir, 'multitarget5.jpg'),
      'JPG12': os.path.join(image_dir, 'brin.jpg'),
      'JPG13': os.path.join(image_dir, 'stepchart.jpg'),
      'JPG14': os.path.join(image_dir, 'testprint.jpeg'),
      'PDF1': os.path.join(image_dir, 'a3color.pdf'),
      'PDF1.2': os.path.join(image_dir, 'PDF1.2.pdf'),
      'PDF1.3': os.path.join(image_dir, 'PDF1.3.pdf'),
      'PDF1.4': os.path.join(image_dir, 'PDF1.4.pdf'),
      'PDF1.5': os.path.join(image_dir, 'PDF1.5.pdf'),
      'PDF1.6': os.path.join(image_dir, 'PDF1.6.pdf'),
      'PDF1.7': os.path.join(image_dir, 'PDF1.7.pdf'),
      'PDF2': os.path.join(image_dir, 'boardingpass.pdf'),
      'PDF3': os.path.join(image_dir, 'letter_p.pdf'),
      'PDF4': os.path.join(image_dir, 'lorem.pdf'),
      'PDF5': os.path.join(image_dir, 'malformatted.pdf'),
      'PDF6': os.path.join(image_dir, 'margin-test.pdf'),
      'PDF7': os.path.join(image_dir, 'noise.pdf'),
      'PDF8': os.path.join(image_dir, 'pickrpt.pdf'),
      'PDF9': os.path.join(image_dir, 'printtest.pdf'),
      'PDF10': os.path.join(image_dir, 'rosemary.pdf'),
      'PDF11': os.path.join(image_dir, 'Satake_AE_web.pdf'),
      'PDF12': os.path.join(image_dir, 'ticket.pdf'),
      'PDF13': os.path.join(image_dir, 'version4pdf.pdf'),
      'PDF14': os.path.join(image_dir, 'YourTickets.pdf'),
      'PNG1': os.path.join(image_dir, 'A4testpage.png'),
      'PNG2': os.path.join(image_dir, 'dna_overview.png'),
      'PNG3': os.path.join(image_dir, 'gcpbeta.png'),
      'PNG4': os.path.join(image_dir, 'google_logo.png'),
      'PNG5': os.path.join(image_dir, 'printtest.png'),
      'PNG6': os.path.join(image_dir, 'printtest2.png'),
      'PNG7': os.path.join(image_dir, 'testpage.png'),
      'PNG8': os.path.join(image_dir, 'larrypage.png'),
      'PNG9': os.path.join(image_dir, 'mandlebulb_3d_test.png'),
      'SVG1': os.path.join(image_dir, 'DoNotDisturb.svg'),
      'SVG2': os.path.join(image_dir, 'Example.svg'),
      'TIFF1': os.path.join(image_dir, 'gcpreglink.tif'),
      'TIFF2': os.path.join(image_dir, 'marbles.tif'),
      'PWG1': os.path.join(image_dir, 'testpage-600-srgb8.pwg'), # Below are in pwg-raster format, 600 DPI, SRGB8
      'PWG2': os.path.join(image_dir, 'rosemary-600-srgb8.pwg'),
      'PWG3': os.path.join(image_dir, 'dna_overview-600-srgb8.pwg'),
      }

  LOGFILES = '/tmp/logocert/'

  OAUTH = 'https://accounts.google.com/o/oauth2/auth'
  OAUTH_TOKEN = 'https://www.googleapis.com/oauth2/v3/token'

  PRINTER = {
      'CERTID': '<certification_id>',
      'FIRMWARE': '<Firmware Version>',
      'IP': '<ip_address of printer>',
      'MANUFACTURER': '<Printer Manufacturer>',
      'MODEL': '<Printer Model>',
      'NAME': '<Printer Name>',
      'PORT': '<integer value of port number of device web service>',
      'SERIAL': '<Printer Serial Number>',
      'STATUS': '<Released, Internal, ProtoType, Unknown>',
      }

  TEST = {
      'NAME': 'LogoCertification_Results',
      'RESULTS': ['Test Case ID', 'Test Case Name', 'Status', 'Notes','','','','Re-run Cmd line'],
      'SPREADSHEET': True,
      'RUN':[     # Order matters, prefix with '#' to skip the test
                  # Update this each time new test classes are added or class names have changed in testcert.py
                'SystemUnderTest',
                'Privet',
                'PreRegistration',
                'Registration',
                'PostRegistration',
                'LocalDiscovery',
                'LocalPrinting',
                'Printer',
                'PrinterState',
                'JobState',
                'CloudPrinting',
                'RunAfter24Hours',
                'Unregister',
            ],
      }

  TESTENV = {
      'ANDROID': '<Android Version>',
      'PYTHON': '<Python Version>',
      'OS': '<OS Name>',
      'TABLET': '<Tablet Version>',
      }

  URL = {
      'TIMEOUT': 20,
      }

  USER = {
      'CLIENT_ID': '<OAuth2_Client_ID_of_test_account>',
      'CLIENT_SECRET': '<OAuth2_Client_Secret_of_test_account>',
      'EMAIL': '<test_account@gmail.com>',
      'PW': '<password of test account.>',
      }

  USER2 = {
      'EMAIL': '<test_account2@gmail.com>',
      'PW': '<password of 2nd test account>',
      }
