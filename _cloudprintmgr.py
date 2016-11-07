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

  @Retry(3, return_type='Value')
  def GetPrinterName(self, printer_name):
    """Get the printer name from the Cloud Print Management page.

    Args:
      printer_name: string (or unique partial string) of printer.
    Returns:
      string: name of printer found on printer details page.
    """
    if self.OpenPrinterDetails(printer_name):
      printer_name = self.cd.FindClass('cp-printerdetailscontent-printer-name')
      if not printer_name:
        self.logger.error('Error finding printer name from details page.')
        return None
      return printer_name.text
    else:
      self.logger.error('Error opening printer details from GCP Mgt page.')
      return None

  def GetPrinterState(self, printer_name):
    """Get the current basic state of a printer.

    Args:
      printer_name: string, name (or unique partial name) of printer.
    Returns:
      string, basic state message.
    """
    if self.OpenPrinterDetails(printer_name):
      state = self.cd.FindClass('cp-printerdetailscontent-basic')
      if state:
        status = self.cd.FindClass('cp-printer-state-message', obj=state)
      else:
        self.logger.error('Error finding basic printer details content.')
        return None
      if not status:
        self.logger.error('Error finding printer state message.')
        return None
      return status.text
    else:
      self.logger.error('Error opening printer details page.')
      return None

  def GetPrinterErrorState(self, printer_name):
    """Determine if cp-error-state-icon is present.

    Args:
      printer_name: string, name (or partial unique name) of printer.
    Returns:
      boolean: True = in error state, False = not in error state.
    """
    if self.SelectPrinter(printer_name):
      selected = self.cd.FindClass('cp-dashboard-listitem-selected')
      if selected:
        error_state = self.cd.FindClass('cp-error-state-icon', obj=selected)
        if error_state:
          return True
      else:
        self.logger.error('%s not selected.', printer_name)
    else:
      self.logger.error('Error finding and seleecting %s', printer_name)

    return False

  def GetPrinterWarningState(self, printer_name):
    """Determine if cp-warning-state-icon is present.

    Args:
      printer_name: string, name (or partial unique name) of printer.
    Returns:
      boolean: True = in warning state, False = not in warning state.
    """
    if self.SelectPrinter(printer_name):
      selected = self.cd.FindClass('cp-dashboard-listitem-selected')
      if selected:
        warning_state = self.cd.FindClass('cp-warning-state-icon', obj=selected)
        if warning_state:
          return True
      else:
        self.logger.error('%s not selected.', printer_name)
    else:
      self.logger.error('Error finding and seleecting %s', printer_name)

    return False

  def GetPrinterStateMessages(self, printer_name):
    """Get all of the printer detailed messages.

    Args:
      printer_name: string, name (or unique partial name) of printer.
    Returns:
      dictionary, keys are labels, values are lists of messages.
    """
    state_messages = {}
    if self.OpenPrinterDetails(printer_name):
      elements = self.cd.FindXPaths('//*[@class="cp-printerdetailscontent-state"]//*[@class="cp-info-label" or @class="cp-printer-state-message"]')
      if elements:
        for element in elements:
          cls = element.get_attribute("class")
          if 'cp-info-label' == cls:
            messages = []
            state_messages.update({element.text: messages})
          elif 'cp-printer-state-message' == cls:
            messages.append(element.text)
      else:
        self.logger.error('No printer state messages found.')
    else:
      self.logger.error('Error opening printer details page.')

    return state_messages

  def GetPrinterDetails(self, printer_name):
    """Get advanced details contained in management page.

    Args:
      printer_name: string, name (or unique partial name) of printer.
    Returns:
      dictionry of key value pairs of printer details.
    """
    details = {}
    if self.OpenPrinterDetails(printer_name):
      time.sleep(2)  # Needed or the Toggle advanced details may fail.
      if self.TogglePrinterAdvancedDetails():
        time.sleep(2)
        adv_details = self.cd.FindClass(
            'cp-printerdetailscontent-advanced-container')
        if not adv_details:
          self.logger.error('Error finding printer advanced details container.')
          return None
        labels = self.cd.FindClasses('cp-info-label', obj=adv_details)
        if not labels:
          self.logger.error('Error finding cp-info-labels')
          return None
        values = self.cd.FindClasses('cp-info-value', obj=adv_details)
        if not values:
          self.logger.error('Error finding cp-info-values')
          return None

        for i in xrange(values.__len__()):
          details[labels[i].text] = values[i].text
      else:
        self.logger.error('Error toggling printer advanced details.')
    else:
      self.logger.error('Error opening printer details.')

    return details

  @Retry(3)
  def TogglePrinterAdvancedDetails(self, toggle=True):
    """Toggle the advanced details page of a printer.

    Args:
      toggle: boolean, True = open, False = close.
    Returns:
      boolean: True = successful, False = errors.
    """
    adv_button = self.cd.FindClass(
        'cp-printerdetailscontent-advanced-button')
    if not adv_button:
      self.logger.error('Error finding advanced details button.')
      return False
    if adv_button.get_attribute('aria-expanded') == 'false':
      toggled = False
    else:
      toggled = True

    if toggle == toggled:
      return True
    else:
      if not self.cd.ClickElement(adv_button):
        self.logger.error('Error toggling advanced printer details.')
        return False

    return True

  def DeletePrinter(self, printer_name):
    """Delete a registered printer using the printer name.

    Args:
      printer_name: string, name (or unique partial name) of printer.
    Returns:
      boolean: True = deleted, False = not deleted.
    """
    if self.SelectPrinter(printer_name):
      delete_buttons = self.cd.FindNames('cp-button-delete')
      for b in delete_buttons:
        if 'Delete' in b.text:
          if not self.cd.ClickElement(b):
            return False
      delete_ok = self.cd.FindName('ok')
      if not delete_ok:
        return False
      if not self.cd.ClickElement(delete_ok):
        return False
      else:
        return True
    else:
      self.logger.warning('Printer not found in registered printer list.')

    return False

  def UpdatePrinterWithUpdateAPI(self, printer_id, option, value):
    """Send an update to the printer using the UPDATE API.

    Args:
      printer_id: string, ID of printer.
      option: string, which option to update.
      value: string, value to give option.
    Returns:
      boolean: True = update submitted, False = errors detected.
    """
    params = {'local_settings': 'update_local_settings'}
    if option not in params:
      self.logger.error('Unknown option for Update API.')
      self.logger.error('Options should be one of: ')
      for param in params:
        self.logger.error('%s', param)
      return False

    self.cd.Get(Constants.GCP['SIMULATE'])

    update_printer_id = self.cd.FindID('update_printerid')
    if not update_printer_id:
      self.logger.error('Could not find printer id in Update section.')
      return False
    if not self.cd.SendKeys(printer_id, update_printer_id):
      self.logger.error('Error entering printer ID in update API section.')
      return False
    option_input = self.cd.FindID(params[option])
    if not option_input:
      self.logger.error('Error finding %s input field', option)
      return False
    if not self.cd.SendKeys(value, option_input):
      self.logger.error('Error inputting %s into input field.', value)
      return False
    submit_button = self.cd.FindID('update_submit')
    if not submit_button:
      self.logger.error('Error findind submit button.')
      return False
    if not self.cd.ClickElement(submit_button):
      self.logger.error('Error clicking submit button for Update API.')
      return False
    return True

  def OpenWebPrintDialog(self):
    """Open the web based print dialog using the print gadget.

    Returns:
      boolean: True = dialog open, False = dialog not open.
    """
    self.cd.Get(Constants.GCP['SIMULATE'])

    gadget = self.cd.FindID('cloudprint_gadget_document')
    if gadget:
      print_button = self.cd.FindClass('__gcp_button_img_cls', obj=gadget)
      if print_button:
        if self.cd.ClickElement(print_button):
          return True
        else:
          self.logger.error('Error clicking print gadget button.')
      else:
        self.logger.error('Error finding print button from print gadget.')
    else:
      self.logger.error('Error findingt he cloudprint gadget on simulate page.')

    return False

  def PrintFromWebDialog(self, printer_name):
    """Select a printer and print from the Web Print Dialog.

    Args:
      printer_name: string, name (or partial unique name) of printer.
    Returns:
      boolean: True = printer selected and printed to, False = errors.
    This method assumes the web print dialog is open.
    """
    printer_found = False
    if self.OpenWebPrintDialog():
      if self.cd.SwitchFrame('__gcp_dialog_iframe_cls', tagname='iframe'):
        printers = self.cd.FindClasses('cp-printdialog-printer-name')
        if printers:
          for p in printers:
            if printer_name in p.text:
              printer_found = True
              if self.cd.ClickElement(p):
                controls = (
                    self.cd.FindClass('cp-printdialog-printwidget-controls'))
                if controls:
                  print_button = self.cd.FindName('print', obj=controls)
                  if print_button:
                    if self.cd.ClickElement(print_button):
                      return True
                    else:
                      self.logger.error('Error selecting the print button.')
                  else:
                    self.logger.error('Error finding the print button.')
                else:
                  self.logger.error('Error finding printwidget controls.')
              else:
                self.logger.error('Error selecting the printer in web dialog.')
          if not printer_found:
            self.logger.warning('Printer not found in web print dialog.')
        else:
          self.logger.error('Printers not found in web print dialog.')
      else:
        self.logger.error('Unable to switch to the web print dialog frame.')
    else:
      self.logger.error('Error opening Web Print Dialog')

    return False

  @Retry(3)
  def SelectJob(self, job_name):
    """Select a job from the management page.

    Args:
      job_name: string, name (or unique partial name) of print job.
    Returns:
      boolean: True = job selected, False = job not selected.
    """
    self.cd.Get(Constants.GCP['MGT'])

    # If job already selected return true.
    selected = self.cd.FindClass('cp-dashboard-listitem-selected')
    if selected:
      jobs = self.cd.FindClasses('cp-job-name', obj=selected)
      for j in jobs:
        if job_name in j.text:
          return True
    jobs = self.cd.FindClasses('cp-job-name')
    for j in jobs:
      if job_name in j.text:
        if self.cd.ClickElement(j):
          return True
    return False

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

  @Retry(3)
  def DeleteJob(self, job_name):
    """Delete a print job from the management page.

    Args:
      job_name: string, name (or unique partial name) of print job.
    Returns:
      boolean: True = job deleted, False = errors deleting job.
    """
    if self.SelectJob(job_name):
      delete_button = self.cd.FindName('cp-button-delete')
      if delete_button:
        if self.cd.ClickElement(delete_button):
          return True
        else:
          self.logger.error('Error clicking delete button.')
      else:
        self.logger.error('Error finding delete button.')
    else:
      self.logger.error('Error selecting job %s', job_name)
    return False

  @Retry(3)
  def OpenJobDetails(self, job_name):
    """Open the details of a print job on the management page.

    Args:
      job_name: string, name or unique partial name of a print job.
    Returns:
      boolean: True = details page opened, False = errors opening details page.
    """
    if self.SelectJob(job_name):
      details_button = self.cd.FindName('cp-button-details')
      if details_button:
        if self.cd.ClickElement(details_button):
          return True
        else:
          self.logger.error('Error selecting print job details button.')
      else:
        self.logger.error('Error finding print job details button.')
    else:
      self.logger.error('Error finding print job  on management page.')
    return False

  @Retry(3, return_type='Value')
  def GetJobStatus(self, job_name):
    """Get the job status of job_name.

    Args:
      job_name: string, name (or unique partial name) of print job.
    Returns:
      string, status of job.
    """
    if self.SelectJob(job_name):
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

  @Retry(3, return_type='Value')
  def GetJobDetailsStateMsg(self, job_name):
    """Get print job details state cause message.

    Args:
      job_name: string, name or unique partial name of print job.
    Returns:
      string, the print job details state cause message.
    """
    if self.OpenJobDetails(job_name):
      state_msg = self.cd.FindClass('cp-jobdetailscontent-state-cause-message')
      if state_msg:
        return state_msg.text
      else:
        self.logger.info('No print job details state cause message found.')
    else:
      self.logger.info('Error opening print job details page.')
    return None

  def GetPagesPrinted(self, job_name):
    """Get the number of pages printed from a print job.

    Args:
      job_name: string, name (or partial unique name) of print job.
    Returns:
      integer, number of pages printed. 0 means job not printed.
    """
    pages_printed = 0
    job_status = self.GetJobStatus(job_name)
    if job_status == 'Printed':
      if self.OpenJobDetails(job_name):
        pp = self.cd.FindXPath("//*[contains(text(), 'Pages printed')]")
        if pp:
          pages_printed = pp.text.split(':')[1]
        else:
          self.logger.error('Error finding Pages printed.')
      else:
        self.logger.error('Error opening print job details page.')
    else:
      self.logger.error('Job not printed or not found.')

    return int(pages_printed)

  def WaitJobStatusNotIn(self, job_name, job_status_list, timeout=600):
    """Wait until the job status becomes a status which is not in the list.

    Args:
      job_name: string, name (or partial unique name) of print job.
      job_status_list: string, list of job status.
      timeout: integer, number of seconds to wait.
    Returns:
      string, current status of job.

    """
    start = time.time()
    while True:
      job_status = self.GetJobStatus(job_name)
      if  job_status not in job_status_list:
        return job_status
      if timeout < time.time() - start:
        return job_status
      time.sleep(1)

  def WaitForJobState(self, job_name, state):
    """Wait until the jobstate is equal to the expected state.

    Args:
      job_name: string, name (or partial unique name) of print job.
      state: string, the expected state
    Returns:
      string, current status of job.

    """
    t_end = time.time() + 60 * 10

    while time.time() < t_end:
      if state == self.GetJobStatus(job_name):
        return state
      time.sleep(1)

    return self.GetJobStatus(job_name)
