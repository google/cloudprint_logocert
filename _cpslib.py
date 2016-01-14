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

delete
deletejob
jobs
list
printer
register
search
submit

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
  def Delete(self, printer_id):
    """Delete a printer owned by a user.

    Args:
      printer_id: string, printerid of registered printer.
    Returns:
      url: string, url to delete printer.
    """
    url = '%s/delete?printerid=%s' % (Constants.GCP['MGT'], printer_id)

    return url

  @InterfaceQuery
  def DeleteJob(self, job_id):
    """Delete a job owned by user.

    Args:
      job_id: string, jobid of existing job owned by user.
    Returns:
      url: string, url to delete job.
    """
    url = '%s/deletejob?jobid=%s' % (Constants.GCP['MGT'], job_id)

    return url

  @InterfaceQuery
  def Jobs(self, printer_id=None, owner=None, job_title=None, status=None):
    """Get a list of print jobs which user has permission to view.

    Args:
      printer_id: string, filer jobs sent to this printer.
      owner: string, filter jobs submitted by this owner.
      job_title: string, filter jobs whose title or tags contain this string.
      status: string, filter jobs that match this status.
    Returns:
      string, url to be used by InterfaceQuery method.
    Valid Job Status strings are: QUEUED, IN_PROGRESS, DONE, ERROR, SUBMITTED,
    and HELD.
    """
    args = '?'
    url = '%s/jobs' % Constants.GCP['MGT']
    if printer_id:
      url += '?printerid=%s' % printer_id
      args = '&'
    if owner:
      url += '%sowner=%s' % (args, owner)
      args = '&'
    if status:
      url += '%sstatus=%s' % (args, status)
      args= '&'
    if job_title:
      url += '%sq=%s' % (args, job_title)

    return url

  @InterfaceQuery
  def List(self, proxy_id):
    """Execute the list interface and return printer fields.

    Args:
      proxy_id: string, proxy of printer.
    Returns:
      string: url to by used by InterfaceQuery method.
    """
    url = '%s/list?proxy=%s' % (Constants.GCP['MGT'], proxy_id)

    return url

  @InterfaceQuery
  def Printer(self, printer_id):
    """Execute the printer interface and return printer fields and capabilites.

    Args:
      printer_id: string, id of printer.
    Returns:
      string: url to be used by InterfaceQuery method.
    """
    fields = 'connectionStatus,semanticState,uiState,queuedJobsCount'
    url = '%s/printer?printerid=%s&usecdd=True&extra_fields=%s' % (
        Constants.GCP['MGT'], printer_id, fields)

    return url

  @InterfaceQuery
  def Search(self, printer=None):
    """Search for printers owned by user.

    Args:
      printer: string, name or partial name of printer to search for.
    Returns:
      string: url to be used by InterfaceQuery method.
    """
    url = '%s/search' % Constants.GCP['MGT']
    if printer:
      url += '?q=%s' % printer

    return url
