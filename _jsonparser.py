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


Json parsing module for the LogoCert package.

Use this module to handle parsing JSON messages into python dictionies, or for
packaging up various artifacts into JSON formatted messages.
"""

import json


class JsonParser(object):
  """Various methods to parse JSON formatted messages."""

  def __init__(self, logger):
    """Pass in the logger object.
    
    Args:
      logger: initialized logger object.
    """
    self.logger = logger

  def Read(self, json_str):
    """Read a json string into a python object.

    Args:
      json_str: string, json response message.
    Returns:
      dictionary of deserialized json string.
    """
    j = {}
    try:
      j = json.loads(json_str)
      j['json'] = True
    except TypeError as e:
      self.logger.error('Error with json string %s\n%s', json_str, e)
      self.logger.error('Ensure input is a string or buffer.')
      j['json'] = False
    except ValueError as e:
      # This means the format from json_str is probably bad.
      self.logger.error('Error parsing json string %s\n%s', json_str, e)
      j['json'] = False

    if not j['json']:
      j['error'] = e

    return j

  def GetValue(self, response, key='message'):
    """Extract the API message from a Cloud Print API json response.

    Args:
      response: json response from API request.
      key: key in json response to get value of.
    Returns:
      string: value of key in json response.
    """
    value = None

    json_dict = self.Read(response)
    # If key is not found, it's possible this is not a JSON response, but
    # rather a HTTP error message, so return response in that case.
    if key in json_dict:
      value = json_dict[key]
      return value
    else:
      return response

  def Print(self, data):
    """Pretty print JSON to the screen and/or log file.

    Args:
      data: JSON string.
    Returns:
      None
    """
    self.logger.info(json.dumps(data, indent=True))

  def Validate(self, response):
    """Return boolean of what is found in response string.

    Args:
      response: string, response from GCP service.
    Returns:
      boolean: True = success, False = not success.
    """
    if response.find('"success": true') > 0:
      return True
    else:
      return False
