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


Methods to interact with the Google Cloud Print Service APIs.

GCPService will provide methods to access all of Cloud Print's Interfaces:

delete (delete printer)
deletejob (delete print job)
jobs (get print jobs)
list (list printers belonging to a specific proxy)
printer (get printer capabilities and info)
register (register a printer)
search (search for printers and return basic information)
submit (submit a print job)

These interfaces are not used in the library, as they are printer specific:

control (used by printer to update job state)
fetch (used by printer to get the next print job)
update (used by printer to update printer attributes)
share (used by applications and interacts with GCP, not printers)
unshare (used by applications and only interacts with GCP, not printers)


This module is dependent on modules from the LogoCert package.
"""
from _common import Sleep
from _common import Extract
from _config import Constants
from _jsonparser import JsonParser
import _log
from _transport import Transport

from json import dumps
from os.path import basename
import requests
import mimetypes
import time

class GCPService(object):
  """Send and receive network messages and communication."""

  def __init__(self, auth_token):
    """Get a reference to a logger object."""
    self.auth_token = auth_token
    self.logger = _log.GetLogger('LogoCert')
    self.jparser = JsonParser(self.logger)
    self.transport = Transport(self.logger)

  def FormatResponse(self, response):
    """Format a JSON reponse from the GCP Service into a dictionary.

    Args:
      response: json response from GCP Service.
    Returns:
      dictionary of keys and values found in response.
    """
    response_dict = {}
    info = self.jparser.Read(response['data'])
    Extract(info, response_dict)

    return response_dict

  def VerifyNotNone(query):
    """Decorator to check that None is not returned. This keeps calling code cleaner

    Args:
      query: function we are wrapping.
    Returns:
      formatted data from query if valid, otherwise raise exception
    """
    def VerifyNotNone(self, *args, **kwargs):
      res = query(self, *args, **kwargs)
      if res is None:
        raise AssertionError
      return res

    return VerifyNotNone


  def InterfaceQuery(query):
    """Decorator for various queries to GCP interfaces

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

  @VerifyNotNone
  def FetchRaster(self, job_id):
    """Get the data content belonging to a job_id in pwg-raster format
       Note: This only works for job_id's that are queued, or in_progress.
             This will not work for jobs that have finished

       Args:
          job_id: string, printer's id
       Returns:
         str, the content in pwg-raster format if successful, otherwise, None

         """
    url = '%s/download?id=%s&forcepwg=1' % (Constants.GCP['MGT'], job_id)
    r = requests.get(url, headers={'Authorization': 'Bearer %s' % self.auth_token})

    if r is None or requests.codes.ok != r.status_code:
      return None

    return r.content



  # Not decorated with @InterfaceQuery since Submit() uses 'requests' instead of '_transport'
  @VerifyNotNone
  def Register(self, printer, printer_id, proxy, cdd_path):
    """Register a printer under the user's account

        Args:
          printer: string, name of printer to register.
          printer_id: string, printer's id.
          proxy: string, network proxy.
          cdd_path: string, file path to the CDD file
        Returns:
          dictionary, response msg from the printer if successful; otherwise, None
            """
    data = {'printer': printer,
            'printerid': printer_id,
            'use_cdd': True,
            'proxy': proxy}

    files = {"capabilities": ('capabilities', open(cdd_path, 'rb'))}
    url = '%s/register' % (Constants.GCP['MGT'])

    r = requests.post(url, data=data, files=files, headers={'Authorization': 'Bearer %s' % self.auth_token})

    if r is None or requests.codes.ok != r.status_code:
      return None

    return r.json()

  # Not decorated with @InterfaceQuery since Submit() uses 'requests' instead of '_transport'
  # 'requests' is chosen because it provides a simple one liner for HTTP Post with files
  @VerifyNotNone
  def Submit(self, printer_id, content, title, cjt=None, is_url=False):
    """Submit a print job to the printer

        Args:
          printer_id: string, target printer to print from.
          content: string, url or absolute filepath of the item to print.
          title: string, title of the print job.
          cjt: CloudJobTicket, object that defines the options of the print job
          is_url: boolean, flag to identify between url's and files
        Returns:
          dictionary, response msg from the printer if successful; otherwise, None
        """

    if cjt is None:
      cjt = {}
    else:
      cjt = cjt.val

    name = content

    if not is_url:
      name = basename(content)
      with open(content, 'rb') as f:
        content = f.read()

    if title is None:
      title = "LogoCert Testing: " + name

    content_type = 'url' if is_url else mimetypes.guess_type(name)[0]
    files = {"content": (name,content)}
    url = '%s/submit' % (Constants.GCP['MGT'])

    data = {'printerid': printer_id,
            'title': title,
            'contentType': content_type,
            'ticket': dumps(cjt)}

    r = requests.post(url, data = data, files = files , headers= {'Authorization': 'Bearer %s' % self.auth_token})

    if r is None or requests.codes.ok != r.status_code:
      return None

    res = r.json()
    res['success'] = res['success'] and 'print job added' in res['message'].lower() #TODO may have to fuzzy match here, print job added may not be a standard
    return res

  # Not decorated with @InterfaceQuery since Update() uses 'requests' instead of '_transport'
  @VerifyNotNone
  def Update(self, printer_id, setting):
    """Update a cloud printer

        Args:
          printer_id: string, target printer to update.
          setting: dict, local settings structure that describes the fields to update
        Returns:
          dictionary, response msg from the printer
        """
    url = '%s/update' % (Constants.GCP['MGT'])

    data = {'printerid': printer_id,
            'local_settings': dumps(setting)}

    r = requests.post(url, data=data, headers={'Authorization': 'Bearer %s' % self.auth_token})

    if r is None or requests.codes.ok != r.status_code:
      return False

    res = r.json()
    res['success'] = res['success'] and 'printer updated successfully' in res['message'].lower() #TODO may have to fuzzy match here, print job added may not be a standard
    return res


  @VerifyNotNone
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

  @VerifyNotNone
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

  @VerifyNotNone
  @InterfaceQuery
  def Jobs(self, printer_id=None, owner=None, job_title=None, status=None):
    """Get a list of print jobs which user has permission to view.

    Args:
      printer_id: string, filter jobs sent to this printer.
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

  @VerifyNotNone
  @InterfaceQuery
  def List(self, proxy_id):
    """Execute the list interface and return printer fields.

    Args:
      proxy_id: string, proxy of printer.
    Returns:
      string: url to by used by InterfaceQuery method.
    Note: the List interface returns the same information as the Search
    interface; therefore, use the Search interface unless you need a list
    or printers using the same proxy_id.
    """
    url = '%s/list?proxy=%s' % (Constants.GCP['MGT'], proxy_id)

    return url

  @VerifyNotNone
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

  @VerifyNotNone
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


  def __getJobFromList(self, job_list, job_id):
    """Find the specified job_id in a list of jobs

    Args:
      job_list: array, job objects.
      job_id: the job_id to look for
    Returns:
      object: the job object with the specified job_id
    """
    for entry in job_list:
      if entry['id'] == job_id:
        return entry
    return None

  def GetJobInfo(self, job_id, printer_id, owner=None, job_title=None):
      """Find the specified job_id in from the Job query result

          Args:
            job_id: string, id of the print job.
            printer_id: string, id of the printer
            owner: string, filter jobs submitted by this owner.
            job_title: string, filter jobs whose title or tags contain this string.
          Returns:
            object: the job object with the specified job_id
      """
      res = self.Jobs(printer_id=printer_id, owner=owner, job_title=job_title)
      job = self.__getJobFromList(res['jobs'], job_id)
      return job

  @VerifyNotNone
  def WaitJobStatusNotIn(self, job_id, printer_id, job_status_list, timeout=600):
    """Wait until the job status becomes a status which is not in the list.

    Args:
      job_id: string, id of the print job.
      printer_id: string, id of the printer
      job_status_list: string, list of job status.
      timeout: integer, number of seconds to wait.
    Returns:
      string, current job.

    """
    end = time.time() + timeout

    while time.time() < end:
      job = self.GetJobInfo(job_id, printer_id)

      if job is not None:
        if job['status'] not in job_status_list:
          return job

      Sleep('POLL')

    return None

  @VerifyNotNone
  def WaitJobStatus(self, job_id, printer_id, job_status, timeout=600):
    """Wait until the job status becomes the specified status

    Args:
      job_id: string, id of the print job.
      printer_id: string, id of the printer
      job_status: string, list of job status.
      timeout: integer, number of seconds to wait.
    Returns:
      dict, current job.

    """
    end = time.time() + timeout

    while time.time() < end:
      job = self.GetJobInfo(job_id, printer_id)

      if job is not None:
        if job['status'] == job_status:
          return job

      Sleep('POLL')

    return None


  def WaitForUpdate(self, dev_id, key, expected_value, timeout=30):
    '''Wait until the printer's local_settings attribute matches an expected value

      Args:
        dev_id: string, id of the printer.
        key: string, the local_settings attribute to poll for.
        expected_value: int or boolean, the expected value of the local_settings attribute.
        timeout: integer, number of seconds to wait.
      Returns:
        boolean, True if expected value is observed, otherwise False
    '''
    end = time.time() + timeout

    while time.time() < end:
      # Continue to use the /Update to access the current local settings
      try:
        res = self.Update(dev_id,{})
      except AssertionError:
        print 'GCP Update call failed'
        return False
      else:
        cur_val = res['printer']['local_settings']['current'][key]
        if expected_value == cur_val:
          return True
      Sleep('POLL')
    return False

