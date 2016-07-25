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


This is a Page Object for Chrome, used by the Logo Cert tool.

Use this page to access resources that are contained within Chrome. No actual
test code should be in this file, only methods to provide resources to tests.
"""

import time

from _common import Retry
from _config import Constants

from selenium.common.exceptions import NoSuchWindowException


class Chrome(object):
  """The Page Object for Chrome."""

  def __init__(self, logger, chromedriver):
    """Set the resources that will be used for the life of this page object.

    Args:
      logger: initialized logger object.
      chromedriver: initialized webdriver object using Chrome.
    """
    self.logger = logger

    self.cd = chromedriver
    self.chrome_version = 'Unknown'
    self.platform = 'Unknown'

    self.devices = 'chrome://devices'
    self.flags = 'chrome://flags'
    self.printpage = 'chrome://print'
    self.settings = 'chrome://settings'
    self.signin = 'chrome://chrome-signin'
    self.version = 'chrome://version'
    self.tokens = {}

    self.GetVersion()

  def DevicePage(self):
    self.cd.driver.get(self.devices)

  def GetFlags(self):
    self.cd.driver.get(self.flags)

  def GetSettings(self):
    self.cd.driver.get(self.settings)

  def GetVersion(self):
    """Get the version of Chrome and the OS.

    Returns:
      boolean: True = set versions, False = error getting versions.
    """
    self.cd.driver.get(self.version)
    version = self.cd.FindID('version')
    os = self.cd.FindID('os_type')
    if version:
      self.chrome_version = version.text
    else:
      return False
    if os:
      self.platform = os.text
    else:
      return False
    return True

  def PrintPage(self):
    self.cd.driver.get(self.printpage)

  def Print(self):
    """This method will open the Chrome Print Dialog.

    Returns:
      boolean:
        True = Print Dialog opened and switch to print dialog window.
        False = errors detected when opening print dialog.
    This simulates selecting CTRL+P in Chrome, and changes chromedriver's
    window to the newly opened print dialog.
    """
    self.cd.driver.execute_script('setTimeout(function(){window.print();},0);')
    if self.SwitchToPrintDialog():
      return True
    return False

  def ClosePrintDialog(self):
    """Close the Chrome Print Dialog.

    Returns:
      boolean: True = cancel succeeded, False = detected errors.
    """
    closed = True
    cancel = self.cd.FindCss('button.cancel')
    if not cancel:
      for handle in self.cd.driver.window_handles:
        self.cd.driver.switch_to_window(handle)
        cancel = self.cd.FindCss('button.cancel')
        if cancel:
          break
      if not cancel:
        self.logger.warning('Cancel button not found.')
        closed = False

    if cancel:
      if not self.cd.ClickElement(cancel):
        self.logger.error('Error clicking on Cancel Button.')
        closed = False

    self.cd.driver.switch_to_window(self.cd.window['main'])
    return closed

  def SelectPrinterFromPrintDialog(self, printer_name, localprint=False):
    """Select a printer from the Chrome Print Dialog.

    Args:
      printer_name: string, name of printer.
      localprint: boolean, True = local printing, False = cloud printing.
    Returns:
      boolean: True = printer selected, False = errors detected.
    """
    printer_found = False
    change = self.cd.FindClass('destination-settings-change-button')
    if not change:
      self.logger.error('Error finding change button.')
      return False
    if not self.cd.ClickElement(change):
      self.logger.error('Error selecting change destination button.')
      return False
    time.sleep(3)
    if localprint:
      printer_list = self.cd.FindClass('local-list')
    else:
      printer_list = self.cd.FindClass('cloud-list')
    if not printer_list:
      self.logger.error('Error finding printer list')
      return False
    printers = self.cd.FindClasses('destination-list-item-name',
                                   obj=printer_list)
    if not printers:
      self.logger.error('Error finding printer names in printer list.')
      return False
    for p in printers:
      if printer_name in p.text:
        if not self.cd.ClickElement(p):
          self.logger.error('Unable to select printer.')
          return False
        printer_found = True

    if not printer_found:
      self.logger.warning('Printer not found in printer list.')
      cancel = self.cd.FindClass('cancel-button')
      self.cd.ClickElement(cancel)
    return printer_found

  def SelectPageRangeInPrintDialog(self, page_range):
    """Enter a specific page range to print from Chrome Print Dialog.

    Args:
      page_range: string, page range to print.
    Returns:
      boolean: True = range entered, False = errors detected.
    """
    custom_radio = self.cd.FindClass('page-settings-custom-radio')
    if not custom_radio:
      self.logger.error('Could not find custom page range radio button.')
      return False
    if not self.cd.ClickElement(custom_radio):
      self.logger.error('Error selecting the custom page range radio button.')
      return False
    page_input = self.cd.FindID('page-settings-custom-input')
    if not page_input:
      self.logger.error('Error finding page range input field.')
      return False
    if not self.cd.SendKeys(page_range, page_input):
      self.logger.error('Error entering %s into page range input', page_range)
      return False
    return True

  def SetCopiesInPrintDialog(self, copies):
    """Enter the number of copies to print from Chrome Print Dialog.

    Args:
      copies: integer, number of copies ot print.
    Returns:
      boolean, True = copies set, False= error detected.
    """
    if copies < 2:
      return True
    increment_button = self.cd.FindClass('increment')
    if not increment_button:
      self.logger.error('Error finding increment button.')
    for _ in xrange(copies-1):
      if not self.cd.ClickElement(increment_button):
        self.logger.error('Error clicking copies increment button.')
        return False
    return True

  def SelectOptionInPrintDialog(self, option, param):
    """Select a drop down list option in the Chrome Print Dialog.

    Args:
      option: string, one of ['layout', 'color', 'size', 'margin']
      param: string, which item to select from option.
    Returns:
      boolean: True = option selected, False = errors detected.
    """
    param_found = True
    option_classes = {
        'layout': 'layout-settings-select',
        'color': 'color-settings-select',
        'size': 'settings-select',
        'margin': 'margin-settings-select',
        }
    if option not in option_classes:
      self.logger.error('%s option is not valid', option)
      return False
    # Determine if more settings is expanded or collapsed.
    # If it's expanded, more-settings-icon-plus will not exist.
    more_settings = self.cd.FindClass('more-settings-icon-plus')
    if more_settings:
      if not self.cd.ClickElement(more_settings):
        self.logger.error('Error expanding more settings in print dialog.')
        return False

    print_option = self.cd.FindClass(option_classes[option])
    if not print_option:
      self.logger.error('Error findind %s in print dialog', option)
      return False
    options = self.cd.FindTags('option', obj=print_option)
    if not options:
      self.logger.error('Error getting valid options for %s', option)
      return False
    for opt in options:
      if param in opt.text:
        param_found = True
        if self.cd.ClickElement(opt):
          return True
        else:
          self.logger.error('Error selecting %s in %s', param, option)
        break
    if not param_found:
      self.logger.error('Did not find %s in %s', param, option)
    self.logger.error('Error selecting %s in %s', param, option)
    return False

  def ToggleCheckboxInPrintDialog(self, option, toggle=True):
    """Toggle a checkbox print dialog option.

    Args:
      option: string, checkbox option to toggle.
      toggle: boolean, True = Select Option, False = Do not select option.
    Returns:
      boolean: True = option toggled, False = errors detected.
    """
    checkboxes = {'headers': 'header-footer-checkbox',
                  'duplex': 'duplex-checkbox',
                  'background': 'css-background-checkbox',
                 }
    if option not in checkboxes:
      self.logger.error('Unknown checkbox option specified in print dialog.')
      return False
    # Determine if more settings is expanded or collapsed.
    # If it's expanded, more-settings-icon-plus will not exist.
    more_settings = self.cd.FindClass('more-settings-icon-plus')
    if more_settings:
      if not self.cd.ClickElement(more_settings):
        self.logger.error('Error expanding more settings in print dialog.')
        return False

    checkbox = self.cd.FindClass(checkboxes[option])
    if checkbox:
      self.cd.driver.execute_script('return arguments[0].scrollIntoView();',
                                    checkbox)
      if toggle == checkbox.is_selected():
        return True
      if self.cd.ClickElement(checkbox):
        return True
      else:
        self.logger.error('Error selecting checkbox for option %s', option)
        return False
    else:
      self.logger.error('Error finding checkbox for option %s', option)
      return False

  def PrintFromPrintDialog(self, printer_name, page_range=None, copies=None,
                           layout='Portrait', color=False, margin='Default',
                           size=None, headers=False, duplex=False,
                           background=False, localprint=False):
    """Select a printer with options and print from the Chrome Print Dialog.

    Args:
      printer_name: string, name of the printer.
      page_range: string, range of pages to print.
      copies: integer, number of copies to print.
      layout: string, Portrait or Landscape.
      color: boolean, True = print in color, False = monochrome.
      margin: string, type of margin to use when printing.
      size: string, paper size.
      headers: boolean, True = use headers, False = no headers.
      duplex: boolean, True = use duplex, False = no duplex.
      background: boolean, True = print background images, False = no images.
      localprint: boolean, True=local printing, False = cloud printing.
    Returns:
      boolean: True = printed successfully, False = errors detected.
    """
    checkboxes = {}
    checkboxes['headers'] = headers
    checkboxes['duplex'] = duplex
    checkboxes['background'] = background

    options = {}
    options['layout'] = layout
    options['margin'] = margin
    options['size'] = size
    if color:
      options['color'] = 'Color'
    else:
      options['color'] = 'Black and white'

    printed = False
    if not self.Print():
      self.logger.error('Error opening and switching to print dialog.')
      self.ClosePrintDialog()
      self.cd.driver.switch_to_window(self.cd.window['main'])
      return False

    if not self.SelectPrinterFromPrintDialog(printer_name,
                                             localprint=localprint):
      self.logger.error('Unable to select printer in print dialog.')
      self.ClosePrintDialog()
      self.cd.driver.switch_to_window(self.cd.window['main'])
      return False
    if page_range:
      if not self.SelectPageRangeInPrintDialog(page_range):
        self.logger.error('Error entering page range in print dialog.')
    if copies:
      if not self.SetCopiesInPrintDialog(copies):
        self.logger.error('Error entering number of copies to print.')
    for opt in options:
      if options[opt]:
        if not self.SelectOptionInPrintDialog(opt, options[opt]):
          self.logger.error('Error setting %s to %s', opt, options[opt])
    for opt in checkboxes:
      if not self.ToggleCheckboxInPrintDialog(opt, checkboxes[opt]):
        self.logger.error('Error toggling %s to %s', opt, checkboxes[opt])
    print_header = self.cd.FindID('print-header')
    if not print_header:
      self.logger.error('Error finding print-header.')
    else:
      print_button = self.cd.FindClass('print', obj=print_header)
      if not print_button:
        self.logger.error('Error finding print button.')
      else:
        if self.cd.ClickElement(print_button):
          printed = True
          self.WaitForPrintDialogToClose()
    self.cd.driver.switch_to_window(self.cd.window['main'])
    return printed

  def PrintGoogleItem(self, printer_name, localprint=False):
    """Print a Google Doc or Message from Chrome.

    Args:
      printer_name: string, name of printer.
      localprint: boolean, True = use local print, False = use cloud print.
    Returns:
      boolean: True = no errors detected, False = errors detected.
    This method assumes you have opened the message or document for printing.
    """
    doctype = {
        'gmail': False,
        'doc': False,
        'sheet': False,
        }
    printed = True
    # Click in body to reveal all labels.
    body = self.cd.FindTags('body')
    for b in body:
      self.cd.ClickElement(b)
      break

    # Mouse over the element so it become visible.
    print_labels = self.cd.FindClass('ade')
    self.cd.MouseOver(print_labels)
    print_icon = self.cd.FindCss("div[aria-label='Print all']")
    if print_icon:
      doctype['gmail'] = True
    else:
      print_icon = self.cd.FindID('printButton')
      if print_icon:
        doctype['doc'] = True
      else:
        print_icon = self.cd.FindID('t-print')
        if print_icon:
          doctype['sheet'] = True
        else:
          self.logger.error('Error finding print icon.')
          return False

    if not self.cd.ClickElement(print_icon):
      printed = False
      self.logger.error('Error clicking print icon.')
    else:
      if doctype['sheet']:
        print_button = (
            self.cd.FindCss(
                'button.goog-buttonset-default.goog-buttonset-action'))
        if not print_button:
          self.logger.error('Error finding print button.')
          printed = False
        else:
          if not self.cd.ClickElement(print_button):
            self.logger.error('Error clicking print button.')
            printed = False
    if printed:
      if not self.SwitchToPrintDialog():
        printed = False
      else:
        if not self.SelectPrinterFromPrintDialog(printer_name,
                                                 localprint=localprint):
          self.logger.error('Unable to select printer in print dialog.')
          printed = False
        else:
          print_button = self.cd.FindCss('button.print.default')
          if not print_button:
            self.logger.error('Error finding print button.')
            printed = False
    if printed:
      if not self.cd.ClickElement(print_button):
        self.logger.error('Error clicking print button.')
        printed = False

    if printed:
      self.WaitForPrintDialogToClose()
      # Need to close open print windows from Gmail.
      if doctype['gmail']:
        for handle in self.cd.driver.window_handles:
          self.cd.driver.switch_to_window(handle)
          title = self.cd.driver.title
          if title.startswith('Gmail'):
            self.cd.driver.close()
    self.cd.driver.switch_to_window(self.cd.window['main'])
    return printed

  @Retry(3)
  def SwitchToPrintDialog(self):
    """Find the Print Dialog and switch to it.

    Returns:
      boolean:
        True = print preview found and switched to preview window.
        False = print preview not found.
    """
    # Give print preview time to generate print preview.
    time.sleep(10)
    for handle in self.cd.driver.window_handles:
      try:
        self.cd.driver.switch_to_window(handle)
      except NoSuchWindowException:
        self.logger.warning('Window closed before switching to it.')
      if self.cd.FindID('print-preview'):
        self.logger.info('Found print preview window.')
        return True
    self.logger.warning('Could not find print preview window.')
    return False

  def WaitForPrintDialogToClose(self):
    """Wait for the print dialog to close before returning."""
    retries = 10
    print_preview = True
    while print_preview:
      preview = False
      for handle in self.cd.driver.window_handles:
        try:
          self.cd.driver.switch_to_window(handle)
        except NoSuchWindowException:
          # This indicates the print dialog closed before switching.
          self.logger.warning('Window closed before switching to it.')
        if self.cd.FindID('print-preview'):
          preview = True
      if not preview:
        print_preview = False
      else:
        retries -= 1
        if retries == 0:
          self.ClosePrintDialog()
          break
        time.sleep(5)

  def PrintFile(self, printer_name, filename, collate=False, color=None,
                copies=None, dpi=None, duplex=None, layout=None, pagefit=None,
                pagerange=None, reverse=False, size=None):
    """Print a file using the Cloud Print management page.

    Args:
      printer_name: string, name (or unique partial name) of printer.
      filename: absolute pathanme of file to print.
      collate: boolean, True = collate, False = do not collate.
      color: string ["Color" or "Monochrome"]
      copies: integer, number of copies to print.
      dpi: string, dpi settings to use.
      duplex: string, should equal "Long Edge" or "Short Edge".
      layout: string, one of ["Auto", "Portrait", "Landscape"].
      pagefit: string, ["No Fitting", "Shrink to Page", "Grow to Page",
                        "Fit to Page", "Fill Page"]
      pagerange: string, range of pages to print.
      reverse: boolean, True = reverse order, False = regular order.
      size: string, paper size to use.
    Returns:
      boolean: True = file printed, False = file not printed.
    """
    self.cd.driver.get(Constants.GCP['MGT'])

    print_button = self.cd.FindName('cp-button-print')
    if not print_button:
      return False
    if not self.cd.ClickElement(print_button):
      return False
    if not self.UploadFile(filename):
      return False

    printer_found = self.SelectPrinter(printer_name)

    if printer_found:
      if collate:
        self.SetCheckBox('collate', collate)
      if color:
        self.SetOption('color', color)
      if copies:
        self.SetCopies(copies=copies)
      if dpi:
        self.SetOption('dpi', dpi)
      if duplex:
        self.SetOption('duplex', duplex)
      if layout:
        self.SetOption('orientation', layout)
      if pagefit:
        self.SetOption('fittopage', pagefit)
      if pagerange:
        self.SetRange(pagerange)
      if reverse:
        self.SetCheckBox('reverse-order', reverse)
      if size:
        self.SetOption('media-size', size)

      dialog_print_button = self.cd.FindName('print')
      if not dialog_print_button:
        return False
      # Give the user time to see the selected option.
      time.sleep(2)
      if not self.cd.ClickElement(dialog_print_button):
        return False
    else:
      self.logger.error('Printer not found.')
      return False

    return True

  def UploadFile(self, filename):
    """Upload a file to print.

    Args:
      filename: string, absolute path of filename to upload.
    Returns:
      boolean: True = successful, False = failed to upload file.
    In order for this method to succeed, the print button from the Cloud Print
    Management page should have already been selected.
    """
    upload = self.cd.FindID(':9')
    if not upload:
      return False
    if not self.cd.ClickElement(upload):
      return False
    # Now switcht to the dialog frame.
    dialog_frame = self.cd.FindClass('__gcp_dialog_iframe_cls')
    if not dialog_frame:
      return False
    if not self.cd.SwitchFrame(dialog_frame):
      return False
    # The following code is only when you want to test the actual file
    # selection dialog. Uncomment it to test it.
    #
    # file_select = self.cd.FindLink('Select a file from my computer')
    # if not file_select:
    #   return False
    # if not self.cd.ClickElement(file_select):
    #   return False

    input_file = self.cd.FindXPath('//input[@type="file"]')
    if not input_file:
      return False
    if not self.cd.SendKeys(filename, input_file):
      return False

    return True

  def SelectPrinter(self, printer_name):
    """Select a printer from the web print dialog.

    Args:
      printer_name: string, printer name or unique partial name.
    Returns:
      boolean: True = printer found, False = printer not found.
    """
    printer_found = False
    printers = self.cd.FindClasses('cp-printdialog-printer-name')
    if not printers:
      return False
    for p in printers:
      if printer_name in p.text:
        printer_found = True
        if not self.cd.ClickElement(p):
          return False
    return printer_found

  def SetOption(self, option, value):
    """Set a menu option for a printer capability.

    Args:
      option: string, which printer capability to set.
      value: string, value to set printer option to.
    Returns:
      boolean: True = option set, False = option not set.
    """
    menu_item_found = False
    items = self.GetMenuItems(option)
    if items:
      for item in items:
        if value in item.text:
          menu_item_found = True
          if not self.cd.ClickElement(item):
            return False
    return menu_item_found

  def GetOptions(self, option, printer_name):
    """Get a list of all values for a specific capability.

    Args:
      option: string, specify the capability to get options for.
      printer_name: string, the name (or unique partial name) of the printer.
    Returns:
      list: list of all available options for this menu item.
    """
    values = []
    # Give filename a fake pathname, as this doesn't need to be a real file.
    if 'Windows' in Constants.TESTENV['OS']:
      filename = 'C:/testfile.jpg'
    else:
      filename = '/tmp/testfile.jpg'
      
    self.cd.driver.get(Constants.GCP['MGT'])
    print_button = self.cd.FindName('cp-button-print')
    if not print_button:
      return False
    if not self.cd.ClickElement(print_button):
      return False
    if not self.UploadFile(filename):
      return False

    printer_found = self.SelectPrinter(printer_name)
    if printer_found:
      items = self.GetMenuItems(option)
      for item in items:
        values.append(item.text)

    self.cd.driver.get(Constants.GCP['MGT'])

    return values

  def GetMenuItems(self, option):
    """Get all menu options for specified option.

    Args:
      option: string, capability to get list of options for.
    Returns:
      list of available selections for a given option.
    """
    container = 'cp-capabilities-capabilities-%s-container' % option
    cap = self.cd.FindClass(container)
    if not cap:
      return None
    button = self.cd.FindClass('jfk-select', obj=cap)
    if not button:
      return None
    if not self.cd.ClickElement(button):
      return None
    menus = self.cd.FindClasses('goog-menu-vertical')
    if not menus:
      return None
    for m in menus:
      items = self.cd.FindClasses('goog-menuitem-content', obj=m)
      for i in items:
        if i.text:
          return items
    return None

  def SetCheckBox(self, option, selected):
    """Set a checkbox to correspond to needed value.

    Args:
      option: string, which option to set.
      selected: boolean, True = option on, False = option off.
    Returns:
      boolean: True = option set, False = option not set.
    """
    container = 'cp-capabilities-capabilities-%s-container' % option
    cap = self.cd.FindClass(container)
    if not cap:
      return False
    checkbox = self.cd.FindClass('jfk-checkbox', obj=cap)
    if not checkbox:
      return False
    if selected == checkbox.is_selected():
      return True
    else:
      if not self.cd.ClickElement(checkbox):
        return False
    return True

  def SetRange(self, pages):
    """Set which pages to print.

    Args:
      pages: string, pages to print (i.e. 3-5, 4, 7-10).
    Returns:
      boolean: True = page range set, False = page range not set.
    """
    container = 'cp-capabilities-capabilities-pagerange-container'
    cap = self.cd.FindClass(container)
    if not cap:
      return False
    radio_button = self.cd.FindClass('jfk-radiobutton', obj=cap)
    if not radio_button:
      return False
    if not radio_button.is_selected():
      if not self.cd.ClickElement(radio_button):
        return False
    range_input = self.cd.FindClass('cp-capabilities-pagerange-range-textbox',
                                    obj=cap)
    if not range_input:
      return False
    if not self.cd.SendKeys(pages, range_input):
      return False
    return True

  def SetCopies(self, copies=1):
    """Set the number of copies to print.

    Args:
      copies: integer, number of pages to print.
    Returns:
      boolean: True = copies was set, False = copies was not set.
    """
    if copies < 2:  # 1 is the default number of copies.
      return True
    copy_plus = self.cd.FindClass('cp-capabilities-copies-plusButton')
    if not copy_plus:
      return False
    for _ in xrange(copies-1):
      if not self.cd.ClickElement(copy_plus):
        return False
    return True

  def IsSignedIn(self):
    """Determine if Chrome is signed in with Google account.

    Returns:
      boolean, True = signed in, False = not signed in.
    """
    self.cd.driver.get(self.settings)
    if not self.cd.SwitchFrame('settings'):
      return False
    account = self.cd.FindID('sync-status-text')
    if not account:
      return False
    if 'Signed in' in account.text:
      return True

    return False

  def SignIn(self, username, password):
    """Sign in with a Google Account.

    Args:
      username: string, gmail account.
      password: string, password of gmail account.
    Returns:
      boolean, True = successful login, False = unsuccessful login.
    """
    email_required = True
    self.cd.driver.get(Constants.ACCOUNTS)
    if 'myaccount' not in self.cd.driver.current_url:
      reauth = self.cd.FindID('reauthEmail')
      if reauth:
        if username != reauth.text:
          account_chooser = self.cd.FindID('account-chooser-link')
          self.cd.ClickElement(account_chooser)
          add_account = self.cd.FindID('account-chooser-add-account')
          self.cd.ClickElement(add_account)
        else:
          email_required = False
      if email_required:
        email = self.cd.FindID('Email')
        if not email:
          return False
        else:
          email.clear()
          if not self.cd.SendKeys(username, email):
            return False
      pw = self.cd.FindID('Passwd')
      if not pw:
        next_button = self.cd.FindID('next')
        if next_button:
          if not self.cd.ClickElement(next_button):
            return False
        else:
          self.logger.error('Coud not find next button.')
          return False
        pw = self.cd.FindID('Passwd')
        if not pw:
          self.logger.error('Passwd id not found on next screen.')
          return False
      if not self.cd.SendKeys(password, pw):
        return False
      signin = self.cd.FindID('signIn')
      if not signin:
        self.logger.info('Account is logged in.')
      else:
        if not self.cd.ClickElement(signin):
          return False

    self.cd.driver.get(self.devices)
    login = self.cd.FindID('cloud-devices-login-link')
    if login:
      if login.is_displayed():
        self.cd.driver.get(self.signin)
        print 'Please sign in manually to the chrome sign in page.'
        raw_input('Hit enter when finished.')

    return True

  def GetTokens(self):
    """Get the tokens that are set in Chrome.

    This method should be run after a user is logged in.
    """
    self.cd.driver.get(Constants.GCP['MGT'])
    cookies = self.cd.driver.get_cookies()
    for d in cookies:
      for k in d:
        if k == 'name':
          key = d[k]
        if k == 'value':
          value = d[k]
      self.tokens[key] = value

  def SignOut(self):
    """Sign out of Google account.

    Returns:
      boolean: True = signed out, False = not signed in or error.
    """
    self.cd.driver.get(self.settings)
    if not self.cd.SwitchFrame('settings'):
      return False
    account = self.cd.FindID('start-stop-sync')
    if not account:
      return False
    if not self.cd.ClickElement(account):
      return False
    stop_sync = self.cd.FindID('stop-syncing-ok')
    if not stop_sync:
      return False
    if not self.cd.ClickElement(stop_sync):
      return False
    return True

  def RegisterPrinter(self, printer_name):
    """Register a printer using local discovery.

    Args:
      printer_name: string that matches a new device name.
    Returns:
      boolean: True = printer submitted for registration.
               False = printer not submitted for registration.
    Note: a user account must be logged into Chrome for this to work.
    """
    self.DevicePage()
    pos = self.FindDevice('printers', printer_name)
    if pos > 0:
      reg_btn = self.cd.FindXPaths('//button[contains(text(), "Register")]')
      if not reg_btn:
        return False
      if not self.cd.ClickElement(reg_btn[pos]):
        return False
    else:
      self.logger.error('Printer not found in list of new devices.')
      return False

    register = self.cd.FindID('register-continue-button')
    if not register:
      return False
    if not self.cd.ClickElement(register):
      return False
    return True

  def ConfirmPrinterRegistration(self, printer_name):
    """Confirm that a device is registered.

    Args:
      printer_name: string that matches a the device name.
    Returns:
      boolean: True = registered printer, False = printer not registered.
    """
    self.DevicePage()
    pos = self.FindDevice('cloud-devices', printer_name)
    if pos > 0:
      self.logger.info('%s is registered.', printer_name)
      return True
    else:
      self.logger.info('%s is not registered.', printer_name)
      return False

  def FindDevice(self, div_id, dev_name):
    """Search for printer_name in the list of new devices.

    Args:
      div_id: string of div id on device page.
      dev_name: string (or partial string) of new device.
    Returns:
      integer: position found in list of new devices. 0 means not found.
    """
    self.DevicePage()
    new_devices = self.cd.FindID(div_id)
    if not new_devices:
      return 0
    devices = self.cd.FindClasses('device-info', obj=new_devices)
    if not devices:
      return 0
    dev_num = devices.__len__()
    for i in xrange(dev_num):
      if dev_name in devices[i].text:
        return i+1
    return 0
