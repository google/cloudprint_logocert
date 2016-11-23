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


Interaction with Google Cloud Print Management and Simulate pages.

This class supports various ways to interact with printers and print jobs
using the Google Cloud Print Management page:
https://www.google.com/cloudprint

and the simulate page:
https://www.google.com/cloudprint/simulate.html

This class is dependent on a ChromeDriver object that it will use to interact
with the management page.
"""
import time

from _common import Retry
from _config import Constants


class CloudPrintMgr(object):
  """An object to interact with our management pages."""

  def __init__(self, logger):
    """Use initialized object for logger.
    
    Args:
      logger: initialized logger object.
    """
    self.logger = logger

  def SelectPrinter(self, printer_name):
    """Select a registered printer from the management page.

    Args:
      printer_name: string, name (or unique partial name) of printer.
    Returns:
      boolean: True = printer selected, False = printer not selected.
    """

    PAGE_ID = 'SelectPrinter("' + printer_name + '")'
    if self.cd.page_id == PAGE_ID:
      return True

    self.cd.Get('about:blank')
    self.cd.Get(Constants.GCP['PRINTERS'])

    printers = self.cd.FindClasses('cp-dashboard-printer-name')
    for p in printers:
      if printer_name in p.text:
        if self.cd.ClickElement(p):
          self.cd.page_id = PAGE_ID
          return True
    return False

  @Retry(3)
  def OpenPrinterDetails(self, printer_name):
    """Open Google Cloud Print Management Printer Details page.

    Args:
      printer_name: string, name (or unique partial name) of printer.
    Returns:
      boolean: True = details page opened, False = errors opening details page.
    """

    PAGE_ID = 'OpenPrinterDetails("' + printer_name + '")'
    if self.cd.page_id == PAGE_ID:
      return True

    container = 'cp-dashboard-actionbar-main'
    if self.SelectPrinter(printer_name):
      action_bar = self.cd.FindClass(container)
      if not action_bar:
        return False
      details_button = self.cd.FindXPaths('//*[contains(text(), "Details")]',
                                          obj=action_bar)
      if not details_button:
        self.logger.error('Error finding details button on printer page.')
        return False
      for button in details_button:
        if 'Details' in button.text:
          if self.cd.ClickElement(button):
            self.cd.page_id = PAGE_ID
            return True
          else:
            self.logger.error('Error clicking details button.')
    return False

  @Retry(3)
  def OpenPrinterJobs(self, printer_name):
    """Open Google Cloud Print Management Printer Jobs page.

    Args:
      printer_name: string, name (or unique partial name) of printer.
    Returns:
      boolean: True = details page opened, False = errors opening details page.
    """
    container = 'cp-dashboard-actionbar-main'
    if self.SelectPrinter(printer_name):
      action_bar = self.cd.FindClass(container)
      if not action_bar:
        return False
      jobs_button = self.cd.FindXPaths('//*[contains(text(), "Show Print Jobs")]',
                                          obj=action_bar)
      if not jobs_button:
        self.logger.error('Error finding show print jobs button on printer page.')
        return False
      for button in jobs_button:
        if 'Show Print Jobs' in button.text:
          if self.cd.ClickElement(button):
            return True
          else:
            self.logger.error('Error clicking details button.')
    return False

  @Retry(3)
  def TogglePrinterAdvancedSettings(self, printer_name, toggle=True):
    """Open Google Cloud Print Management Printer Advanced Details tab.

    Args:
      printer_name: string, name of printer.
      toggle: boolean, True = expand, False = collapse.
    Returns:
      boolean: True = advanced settings opened, False = errors detected.
    """
    if not self.OpenPrinterDetails(printer_name):
      self.logger.error('Error opening Printer Details.')
      return False
    advanced = self.cd.FindClass('cp-printerdetailscontent-settings-button')
    if not advanced:
      self.logger.error('Error opening Advanced Details of Printer.')
      return False
    if advanced.get_attribute('aria-expanded') == 'false':
      is_toggled = False
    else:
      is_toggled = True
    if toggle == is_toggled:
      return True
    if self.cd.ClickElement(advanced):
      return True
    else:
      self.logger.error('Error toggling Advanced Settings')
      return False

  @Retry(3)
  def ToggleAdvancedOption(self, printer_name, setting, toggle=True):
    """Toggle and advanced setting checkbox.

    Args:
      printer_name: string, name of printer.
      setting: string, which advanced setting to toggle.
      toggle: boolean, True = select, False = do not select.
    Returns:
      boolean: True = setting toggled, False = errors detected.
    """
    adv_setting = {
        'local_discovery': 'cp-printersettings-local-discovery-row',
        'local_printing': 'cp-printersettings-local-printing-row',
        'conversion': 'cp-printersettings-conversion-printing-row',
        }

    if setting not in adv_setting:
      self.logger.error('unknown setting. Use one of: ')
      for k in adv_setting:
        self.logger.error('%s', k)
      return False
    if not self.TogglePrinterAdvancedSettings(printer_name):
      return False
    row = self.cd.FindClass(adv_setting[setting])
    if not row:
      self.logger.error('Could not find advanced setting.')
      return False
    checkbox = self.cd.FindClass('jfk-checkbox', obj=row)
    if not checkbox:
      self.logger.error('Error finding checkbox for advanced setting.')
      return False
    if checkbox.get_attribute('aria-checked') == 'false':
      is_toggled = False
    else:
      is_toggled = True
    if toggle == is_toggled:
      return True
    if not self.cd.ClickElement(checkbox):
      self.logger.error('Error toggling checkbox.')
      return False
    save_changes = self.cd.FindClass('cp-printersettings-save-changes')
    if not save_changes:
      self.logger.error('Error finding Save button')
      return False
    if not self.cd.ClickElement(save_changes):
      self.logger.error('Error clicking Save button.')
      return False
    return True


  @Retry(3)
  def SelectPrinterJob(self, printer_name, job_name):
    """Select a printer job from the management page.

    Args:
      printer_name: string, name (or unique partial name) of printer.
      job_name: string, name (or unique partial name) of print job.
    Returns:
      boolean: True = job selected, False = job not selected.
    """
    self.OpenPrinterJobs(printer_name)

    # If job already selected return true.
    job = self.cd.FindXPath('//*[@class="cp-job-name" and contains(text(),"' + job_name + '")]')
    if self.cd.ClickElement(job):
      return True
    return False

  @Retry(3, return_type='Value')
  def GetPrinterJobStatus(self, printer_name, job_name):
    """Get the printer job status of job_name.

    Args:
      printer_name: string, name (or unique partial name) of printer.
      job_name: string, name (or unique partial name) of print job.
    Returns:
      string, status of job.
    """
    if self.SelectPrinterJob(printer_name, job_name):
      selected = self.cd.FindClass('cp-dashboard-listitem-selected')
      if selected:
        status = self.cd.FindClass('cp-status-msg', obj=selected)
        if status:
          return status.text
        else:
          return None
      else:
        return None
    else:
      return None

