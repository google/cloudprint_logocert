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


A module to create and populate a Google spreadsheet from test results.

This class depends on the module _gdocs and will interact with a
Google spreadsheet. This class supports placing Logo Certification test results
in a spreadsheet to assist in summarizing the test results.
"""
import _gdocs


class SheetMgr(object):
  """Create and populate a Google spreadsheet."""

  def __init__(self, logger, creds, Constants):
    """ Sheet manager will use some objects from main module.
    
    Args:
      logger: initialized logger object.
      Constants: object that contains contants.
    """
    self.logger = logger
    self.headers = Constants.TEST['RESULTS']
    self.sheet = _gdocs.GoogleDataMgr(logger, creds, Constants)
    # First see if Spreadsheet Already exists.
    self.sheet_id = self.sheet.GetSpreadSheetID(Constants.TEST['NAME'])
    if not self.sheet_id:
      self.sheet.CreateSheet(Constants.TEST['NAME'])
      self.sheet_id = self.sheet.GetSpreadSheetID(Constants.TEST['NAME'])
      if not self.sheet_id:
        # Something went wrong
        self.logger.error('Error creating spreadsheet.')
    self.worksheet_id = self.sheet.GetWorkSheetID(self.sheet_id)

  def MakeHeaders(self):
    """Add column headers to the spreadsheet."""
    if self.sheet.CreateColumnHeaders(self.headers, self.sheet_id,
                                      self.worksheet_id):
      return True
    return False

  def AddRow(self, row):
    """Add a row to an existing spreadsheet with a column header.

    Args:
      row: list of strings to add, number of items must = number of headers.
    Returns:
      boolean: True = row created, False = errors.
    """
    column_names = []
    for header in self.headers:
      formatted_header = ''.join(header.split()).lower()
      column_names.append(formatted_header)
    if self.sheet.AddRowUsingColumnHeaders(column_names, row, self.sheet_id,
                                           self.worksheet_id):
      return True
    return False
