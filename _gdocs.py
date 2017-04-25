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


Support interaction with Google Documents.

This class supports various ways to interact with Google Drive and in particular
Google Spreadsheets. It is dependent on the external module gdata:

https://github.com/google/gdata-python-client
"""
from _config import Constants
from _transport import Transport

import gdata.gauth
import gdata.service
import gdata.spreadsheets
import gdata.spreadsheets.client
import gdata.spreadsheets.data

from googleapiclient import discovery
from httplib2 import Http
import json
import sys

class GoogleDataMgr(object):
  """An object to interact with Google Drive and Docs."""

  def __init__(self, logger, creds, Constants):
    """ Use initialized objects from main module.
    
    Args:
      logger: initialized logger object.
      creds: OAuth2Credentials.
      Constants: object holding constant values.
    """
    self.logger = logger
    self.drive = 'https://drive.google.com'
    self.creds = creds
    self.transport = Transport(self.logger)

    self.token = gdata.gauth.OAuth2Token(
        client_id=Constants.USER['CLIENT_ID'],
        client_secret=Constants.USER['CLIENT_SECRET'],
        scope=Constants.AUTH['SCOPE'],
        access_token=Constants.AUTH['ACCESS'],
        refresh_token=Constants.AUTH['REFRESH'],
        user_agent=Constants.AUTH['USER_AGENT'])
    self.client = gdata.spreadsheets.client.SpreadsheetsClient()
    self.token.authorize(self.client)

  def CreateSheet(self, name):
    """Create a Google Spreadsheet to hold test results.

    Args:
      name: string, name to assign the spreadsheet.
    Returns:
      void - this should not fail
    """
    SHEETS = discovery.build('sheets', 'v4', http=self.creds.authorize(Http()))
    data = {'properties': {'title': name}}
    res = SHEETS.spreadsheets().create(body=data).execute()
    if res is not None and 'spreadsheetId' in res:
      self.logger.info('Created a new google spreadsheet with sheets API.')
      if Constants.TEST['SHARE_SHEET_WITH_GOOGLE']:
        self.logger.info('Attempting to share newly created sheet with Google')
        self.ShareSheet(res['spreadsheetId'])
    else:
      self.logger.info('Failed to create a new google spreadhseet with '
                       'sheets API')

  def ShareSheet(self, id):
    """Share a Google Spreadsheet with Google's GCP certification team.

    Args:
      id: string, Google Sheet id.
    """
    url = 'https://www.googleapis.com/drive/v2/files/%s/permissions' % id

    data = {
      'value': Constants.TEST['GCP_TEAM_EMAIL'],
      'type': 'user',
      'role': 'reader',
    }

    params = {
      'sendNotificationEmails': True,
      'emailMessage': ('New Logocert google sheet shared with you by %s' %
                       Constants.PRINTER['MANUFACTURER'])
    }

    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer %s' % self.token.access_token}

    r = self.transport.HTTPPost(url, data=json.dumps(data), params=params,
                                headers=headers)

    if r is None:
      self.logger.error('Google Drive API returned None response')
      raise

    if r.status_code == 200:
      self.logger.info('Successfully sharing sheet (read-only) with Google: %s'
                       % Constants.TEST['GCP_TEAM_EMAIL'])
      return

    if r.status_code == 403:
      print r.json()['error']['message']
      self.logger.error('API Disabled. Follow the steps below to fix')
      self.logger.error('1) Enable Drive API via link above.')
      self.logger.error('2) Delete the newly created spreadsheet and '
                        're-run this tool.')
    else:
      self.logger.error('ERROR: Google Drive Permission API failed with '
                        'status: %s' % r.status_code)
      print r.text;
    sys.exit()

  def GetSpreadSheetID(self, name):
    """Return the spreadsheet id that has the matching name.

    Args:
      name: string, name (title) of spreadsheet.
    Returns:
      string, the spreadsheet id.
    """
    q = gdata.spreadsheets.client.SpreadsheetQuery(name, 'true')
    try:
      feed = self.client.GetSpreadsheets(query=q)
    except gdata.service.RequestError:
      self.logger.error('Error getting spreadsheet feed.')
      return None

    try:
      sid = feed.entry[0].id.text.rsplit('/', 1)[1]
    except IndexError:
      sid = None
    return sid

  def GetWorkSheetID(self, spreadsheet_id):
    """Return the worksheet id of the spreadsheet with spreadsheet_id.

    Args:
      spreadsheet_id: string, id of existing spreadsheet.
    Returns:
      string, id of worksheet.
    """
    try:
      feed = self.client.GetWorksheets(spreadsheet_id)
    except gdata.service.RequestError:
      self.logger.error('Error getting worksheet feed.')
      return None

    try:
      wid = feed.entry[0].id.text.rsplit('/', 1)[1]
    except IndexError:
      wid = None
    return wid

  def CreateColumnHeaders(self, headers, spreadsheet_id, worksheet_id):
    """Create column headers (columns in row 1) in a spreadsheet.

    Args:
      headers: list of strings for spreadsheet column headers.
      spreadsheet_id: string, id of spreadsheet.
      worksheet_id: string, id of worksheet.
    Returns:
      boolean: True = headers created, False = errors.
    """
    cell_range = 'A1:H1'
    cellq = gdata.spreadsheets.client.CellQuery(range=cell_range,
                                                return_empty='true')
    cells = self.client.GetCells(spreadsheet_id, worksheet_id, q=cellq)
    batch = gdata.spreadsheets.data.BuildBatchCellsUpdate(spreadsheet_id,
                                                          worksheet_id)
    i = 0
    for cell in cells.entry:
      cell.cell.input_value = headers[i]
      batch.add_batch_entry(cell, cell.id.text, batch_id_string=cell.title.text,
                            operation_string='update')
      i += 1
    try:
      self.client.batch(batch, force=True)
    except gdata.service.RequestError:
      self.logger.error('Error adding header in column %d', i)
      return False
    return True

  def AddRowUsingColumnHeaders(self, headers, row_data, spreadsheet_id,
                               worksheet_id):
    """Add a row to an existing spreadsheet with headers.

    Args:
      headers: list of strings that match the column headers.
      row_data: list of strings, 1 for each column.
      spreadsheet_id: string, id of spreadsheet.
      worksheet_id: string, id of worksheet.
    Returns:
      boolean: True = row added, False = errors.
    """
    row = dict(zip(headers, row_data))
    entry = gdata.spreadsheets.data.ListEntry()
    for k in row:
      entry.set_value(k, row[k])
    try:
      self.client.add_list_entry(entry, spreadsheet_id, worksheet_id)
    except gdata.service.RequestError:
      self.logger.error('Error inserting a new row into spreadsheet.')
      return False
    return True
