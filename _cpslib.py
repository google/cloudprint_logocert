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


Methods to interact with the Google Cloud Print Service APIs.

GCPService will provide methods to access all of Cloud Print's Interfaces:

list
search
submit
deletejob
jobs
printer
control
delete
fetch
register
update

This module is dependent on modules from the LogoCert pacakge.
"""

from _common import Extract
from _config import Constants
from _jsonparser import JsonParser
import _log
from _transport import Transport


class GCPService(object):
  """Send and receive network messages and communication."""

  def __init__(self, auth_token):
    """Get a reference to a logger object."""
    self.auth_token = auth_token
    self.logger = _log.GetLogger('LogoCert')
    self.jparser = JsonParser()
    self.transport = Transport()

  def FormatResponse(self, response):
    """Format a JSON reponse from the GCP Service into a dictionary.

    Args:
      response: jason response from GCP Service.
    Returns:
      dictionary of keys and values found in response.
    """
    response_dict = {}
    info = self.jparser.Read(response['data'])
    Extract(info, response_dict)

    return response_dict

  def InterfaceQuery(query):
    """Decorator for all queries to GCP interfaces.

    Args:
      query: function we are wrapping.
    Returns:
      formatted data from query to GCP Service Interface.
    """
    def GCPQuery(self, *args, **kwargs):
      url = query(self, *args, **kwargs)
      res = self.transport.HTTPReq(url, auth_token=self.auth_token)
      return self.FormatResponse(res)

    return GCPQuery

  @InterfaceQuery
  def Search(self, printer=None):
    """Search for printers owned by user.

    Args:
      printer: string, name or partial name of printer to search for.
    Returns:
      json string returned from the GCP Service.
    """
    search_url = Constants.GCP['MGT'] + '/search'
    if printer:
      url = search_url + '?q=%s' % printer
    else:
      url = search_url

    return url

  @InterfaceQuery
  def Printer(self, printer_id):
    """Execute the printer interface and return printer fields and capabilites.

    Args:
      printer_id: string, id of printer.
    Returns:
      json string returned by GCP Service.
    """
    url = '%s/printer?printerid=%s&usecdd=True' % (
        Constants.GCP['MGT'], printer_id)

    return url
