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


Common functions and utilities used across the logocert package.

This provides some common functions and classes that are needed by multiple
classes and modules in the Logo Certification Package.
"""

import time
import os
from _config import Constants

# Module level variable
_use_color_output = (Constants.TEST['FORCE_COLOR_OUTPUT'] or
                     'nt' not in os.name.lower())

def Sleep(wait_type):
  sec = Constants.SLEEP[wait_type]
  if 'POLL' not in wait_type:
    print '[Configurable sleep] %s: %s seconds' %(wait_type, sec)
  time.sleep(sec)

def GreenText(str):
  """Display text in green

      Args:
        str: string, the str to display, cannot be None.
    """
  global _use_color_output

  return str if not _use_color_output else '\033[92m'+str+'\033[0m'

def RedText(str):
  """Display text in red

      Args:
        str: string, the str to display, cannot be None.
    """
  global _use_color_output

  return str if not _use_color_output else '\033[91m'+str+'\033[0m'

def BlueText(str):
  """Display text in blue

      Args:
        str: string, the str to display, cannot be None.
    """
  global _use_color_output

  return str if not _use_color_output else '\033[94m'+str+'\033[0m'

def PurpleText(str):
  """Display text in purple

      Args:
        str: string, the str to display, cannot be None.
    """
  global _use_color_output

  return str if not _use_color_output else '\033[95m' + str + '\033[0m'

def PromptUserAction(msg):
  """Display text in warning color and beep

    Args:
      msg: string, the msg to prompt the user.
    Returns:
      string, prompt string
  """
  print "\a"  # Cross-platform beep
  print PurpleText('[ACTION] '+msg)

def PromptAndWaitForUserAction(msg):
  """Display text in green and beep - cross-platform, then wait for user to
     press enter before continuing

      Args:
        msg: string, the msg to prompt the user.
      Returns:
        string, user input string
  """
  PromptUserAction(msg)
  return raw_input()


def Extract(dict_in, dict_out):
  """Extract all the keys and values from a nested dictionary.

  Args:
    dict_in: dictionary of unknown size and levels.
    dict_out: dictionary to be created.
  """
  if isinstance(dict_in, dict):
    for key, value in dict_in.iteritems():
      if isinstance(value, dict):
        Extract(value, dict_out)
      elif isinstance(dict_in, list):
        for i in dict_in:
          Extract(i, dict_out)
      else:
        dict_out[key] = value
  else:
    type(dict_in)


class Error(Exception):
  """Base class for exceptions in this module.

  Args:
    expr: string, expression that caused the error.
    msg: string, reason for error.
  """

  def __init__(self, expr, msg):
    super(Error, self).__init__()
    self.expr = expr
    self.msg = msg


class InitError(Error):
  """Exception raised for errors in the class initialization.

  Args:
    msg: string, reason for error.
  """

  def __init__(self, msg):
    super(InitError, self).__init__('Error initializing object.', msg)
