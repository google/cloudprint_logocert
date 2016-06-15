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


Common functions and utilities used across the logocert package.

This provides some common functions and classes that are needed by multiple
classes and modules in the Logo Certification Package.
"""

import base64
import json
import math
import mimetypes
import os
import time

from _config import Constants
import _log


def Cancel():
  """Allow for user input to cancel a pending operations.

  Returns:
    Boolean, True = cancel, False = do not cancel.
  This function requires manual user input.
  """
  if raw_input('Press enter to continue or c to cancel: ').lower() == 'c':
    return True
  return False


def Base64Encode(pathname):
  """Convert a file to a base64 encoded file.

  Args:
    pathname: path name of file to base64 encode..
  Returns:
    string, name of base64 encoded file.
  For more info, see:
    http://en.wikipedia.org/wiki/Data_URI_scheme
  """
  b64_pathname = pathname + '.b64'
  file_type = mimetypes.guess_type(pathname)[0] or 'application/octet-stream'
  # We'll skip encoding if it's already been done.
  if not os.path.exists(b64_pathname):
    data = ReadFile(pathname)

    # Convert binary data to base64 encoded data.
    if data:
      header = 'data:%s;base64,' % file_type
      b64data = header + base64.b64encode(data)
    else:
      return None

    if WriteFile(b64_pathname, b64data):
      return b64_pathname
    else:
      return None
  else:
    return b64_pathname


def EncodeMultiPart(fields=None, files=None, ftype='application/xml'):
  """Encodes list of parameters and files for HTTP multipart format.

  Args:
    fields: list of tuples containing name and value of parameters.
    files: list of tuples containing param name filename, and file contents.
    ftype: string if file type different than application/xml.
  Returns:
    An encoded string to be sent as data for the HTTP post request.
  """
  lines = []
  if fields:
    for (key, value) in fields:
      lines.append('--' + Constants.BOUNDARY)
      lines.append('Content-Disposition: form-data; name="%s"' % key)
      lines.append('')  # blank line
      lines.append(value)
  if files:
    for (key, filename, value) in files:
      lines.append('--' + Constants.BOUNDARY)
      lines.append(
          'Content-Disposition: form-data; name="%s"; filename="%s"'
          % (key, filename))
      lines.append('Content-Type: %s' % ftype)
      lines.append('')  # blank line
      # If any strings are unicode, encode them for utf-8.
      for i, line in enumerate(lines):
        if isinstance(line, unicode):
          lines[i] = line.encode('utf-8')
      lines.append(value)
  lines.append('--' + Constants.BOUNDARY + '--')
  lines.append('')  # blank line
  return Constants.CRLF.join(lines)


def Extract(dict_in, dict_out):
  """Extract all the keys and values from a nested dictionary.

  Args:
    dict_in: dictionary of unknown size and levels.
    dict_out: dictionary to be created.
  """
  if isinstance(dict_in, dict):
    keys = dict_in.keys()
    print keys
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


def Retry(attempts, delay=3, backoff=2, return_type='Boolean'):
  """Retries a function or method until it returns True or attempts is reached.

  Args:
    attempts: integer, number of attempts to try.
    delay: integer, the amount of time to wait between attempts.
    backoff: integer, how much time to lengthen the delay between attempts.
    return_type: string, type of return function has. Boolean or Value.
  Returns:
    return value of decorated function.
  Raises:
    ValueError: if the value passed in is not valid.
  """
  if backoff <= 1:
    raise ValueError('backoff must be greater than 1')

  attempts = math.floor(attempts)
  if attempts < 0:
    raise ValueError('tries must be 0 or greater')

  if delay <= 0:
    raise ValueError('delay must be greater than 0')

  def DecoratedRetry(f):
    """The decorated retry function."""
    def FunctionRetry(*args, **kwargs):
      """Retry function, accepting arguments from decorated function."""
      mattempts, mdelay = attempts, delay  # Make them mutable.

      rv = f(*args, **kwargs)
      while mattempts > 0:
        if return_type == 'Boolean':
          if rv is True:
            return rv
        else:
          if rv is not None:
            return rv

        mattempts -= 1
        time.sleep(mdelay)
        mdelay *= backoff

        rv = f(*args, **kwargs)

      return rv  # Ran out of attempts.

    return FunctionRetry
  return DecoratedRetry


def ReadFile(pathname):
  """Read contents of a file and return content.

  Args:
    pathname: string, pathname of the file.
  Returns:
    string, contents of the file.
  """
  logger = _log.GetLogger('LogoCert')
  if os.path.isfile(pathname):
    with open(pathname, 'rb') as f:
      try:
        s = f.read()
        return s
      except IOError as e:
        logger.error('Error reading %s\n%s', pathname, e)
        return None
    return None
  return None


def WriteFile(file_name, data):
  """Write contents of data to a file.

  Args:
    file_name: string, (path)name of file.
    data: string, contents to write to file.
  Returns:
    boolean: True = success, False = errors.
  """
  logger = _log.GetLogger('LogoCert')
  with open(file_name, 'wb') as f:
    try:
      f.write(data)
    except IOError as e:
      logger.error('Error writing %s\n%s', file_name, e)
      return False

  return True


def ReadJsonFile(pathname):
  """Return the contents of a Json file.

  Args:
    pathname: string, pathname of a file.
  Returns:
    string, contents of the file.
  """
  logger = _log.GetLogger('LogoCert')
  if os.path.isfile(pathname):
    try:
      s = json.load(open(pathname))
      return s
    except IOError as e:
      logger.error('Error reading %s\n%s', pathname, e)
      return None
    return None
  return None


def WriteJsonFile(file_name, data):
  """Write contents of json object to a json formatted file.

  Args:
    file_name: string, (path)name of file.
    data: string, contents to write to file.
  Returns:
    boolean: True = success, False = errors.
  """
  logger = _log.GetLogger('LogoCert')
  try:
    json.dump(data, open(file_name, 'wb'))
  except IOError as e:
    logger.error('Error writing %s\n%s', file_name, e)
    return False

  return True


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
