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


Provide a webdriver instance for the CloudPrint Logo Certification Tool.

This code makes use of implicit waits in order to ensure that elements are
present before proceeding, and will continue polling up to the value of timeout
(in seconds).
"""

import os
import time

from selenium import webdriver
from selenium.common.exceptions import ElementNotVisibleException
from selenium.common.exceptions import NoSuchElementException
from selenium.common.exceptions import NoSuchFrameException
from selenium.common.exceptions import TimeoutException
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


class ChromeDriver(object):
  """Provides webdriver functionality for Chrome."""

  def __init__(self, logger, user_data_dir, timeout):
    """Initialize chromedriver for use by all other modules.

    Args:
      logger: initialized logger object.
      user_data_dir: string, directory for chrome data.
      timeout: integer, number of seconds to wait for web pages to load.
    """
    self.timeout = timeout
    data_dir = os.path.join(os.getcwd(), user_data_dir)
    self.logger = logger
    options = Options()
    data_dir_option = '--user-data-dir=%s' % data_dir
    options.add_argument(data_dir_option)
    options.add_argument('--enable-logging')
    options.add_argument('--v=1')
    options.add_argument('--lang=en')
    options.add_argument('--disable-features=UsePasswordSeparatedSigninFlow')
    options.add_experimental_option("windowTypes", ["webview"])
    self.driver = webdriver.Chrome(chrome_options=options)
    self.action_chain = ActionChains(self.driver)

    self.window = {}
    self.window['main'] = self.driver.current_window_handle
    self.window['logocert'] = None

    self.ActionPerformed()

  def ActionPerformed(self):
    """Call this function when any action performed.
      It records current time and resets the 'page_id' field.
    """
    self.last_action_time = time.time()
    self.page_id = None

  def CloseChrome(self):
    self.driver.quit()

  def ClickElement(self, element):
    """Click a web object element.

    Args:
      element: web element object.
    Returns:
      boolean: True = element clicked, False = element not clicked.
    """
    try:
      self.GetWait().until(EC.visibility_of(element))
    except TimeoutException:
      self.logger.error('Timed out because clickable element not visible.')
      return False
    else:
      try:
        element.click()
      except ElementNotVisibleException:
        self.logger.error('Error clicking element.')
        return False
      finally:
        self.ActionPerformed()
      return True

  def ExecScript(self, script):
    """Execute javascript.

    Args:
      script: string, script to execute.
    Returns:
      boolean: True = script executed, False = script not executed.
    """
    try:
      self.driver.execute_script(script)
    except WebDriverException:
      self.logger.error('Error executing %s', script)
      return False
    finally:
      self.ActionPerformed()
    return True

  def FindClass(self, classname, obj=None):
    """Find web element in web page using class name.

    Args:
      classname: string, name of class to search for.
      obj: web element object to search within.
    Returns:
      webelement object with first occurrence of classname.
    """
    try:
      self.GetWait().until(EC.presence_of_element_located((By.CLASS_NAME,
                                                      classname)))
    except TimeoutException:
      self.logger.error('Timed out looking for class: %s', classname)
      return None
    else:
      try:
        if obj:
          element = obj.find_element_by_class_name(classname)
        else:
          element = self.driver.find_element_by_class_name(classname)
      except NoSuchElementException:
        self.logger.error('Error finding %s class name.', classname)
        return None
      return element

  def FindClasses(self, classname, obj=None):
    """Find all web elements with classname.

    Args:
      classname: string, class to search for.
      obj: web element object to search within.
    Returns:
      list of web element objects containing classname.
    """
    try:
      self.GetWait().until(EC.presence_of_all_elements_located((By.CLASS_NAME,
                                                           classname)))
    except TimeoutException:
      self.logger.error('Timed out looking for class: %s', classname)
      return None
    else:
      try:
        if obj:
          elements = obj.find_elements_by_class_name(classname)
        else:
          elements = self.driver.find_elements_by_class_name(classname)
      except NoSuchElementException:
        self.logger.error('Error finding %s class name.', classname)
        return None
      return elements

  def FindCss(self, css, obj=None):
    """Find web element using CSS elements.

    Args:
      css: string, css element to search for.
      obj: web element object to search within.
    Returns:
      web element object that contains css.
    """
    try:
      self.GetWait().until(EC.presence_of_element_located((By.CSS_SELECTOR, css)))
    except TimeoutException:
      self.logger.error('Timed out waiting for css: %s', css)
      return None
    else:
      try:
        if obj:
          element = obj.find_element_by_css_selector(css)
        else:
          element = self.driver.find_element_by_css_selector(css)
      except NoSuchElementException:
        self.logger.error('Element css %s not found', css)
        return None
      return element

  def FindCssElements(self, css, obj=None):
    """Find web elements using CSS elements.

    Args:
      css: string, css elements to search for.
      obj: web element object to search within.
    Returns:
      list of web element objects that contain css.
    """
    try:
      self.GetWait().until(EC.presence_of_all_elements_located((By.CSS_SELECTOR,
                                                           css)))
    except TimeoutException:
      self.logger.error('Timed out looking for css: %s', css)
      return None
    else:
      try:
        if obj:
          elements = obj.find_elements_by_css_selector(css)
        else:
          elements = self.driver.find_elements_by_css_selector(css)
      except NoSuchElementException:
        self.logger.error('Element css %s not found', css)
        return None
      return elements

  def FindID(self, element_id, obj=None):
    """Find web element using web id.

    Args:
      element_id: string, id of web element.
      obj: web element object to search within.
    Returns:
      web element object with element_id.
    """
    try:
      self.GetWait().until(EC.visibility_of_element_located((By.ID, element_id)))
    except TimeoutException:
      self.logger.error('Timed out looking for id: %s', element_id)
      return None
    else:
      try:
        if obj:
          element = obj.find_element_by_id(element_id)
        else:
          element = self.driver.find_element_by_id(element_id)
      except NoSuchElementException:
        self.logger.error('Element id %s not found', element_id)
        return None
      return element

  def FindLink(self, link, obj=None):
    """Find web element using link text.

    Args:
      link: string, link text to search for.
      obj: web element object to search within.
    Returns:
      web element object with link text.
    """
    try:
      self.GetWait().until(EC.presence_of_element_located((By.LINK_TEXT, link)))
    except TimeoutException:
      self.logger.error('Timed out lookinf for link text: %s', link)
      return None
    else:
      try:
        if obj:
          element = obj.find_element_by_link_text(link)
        else:
          element = self.driver.find_element_by_link_text(link)
      except NoSuchElementException:
        self.logger.error('Error finding link text: %s', link)
        return None
      return element

  def FindName(self, name, obj=None):
    """Find web element using name.

    Args:
      name: string, name to search for.
      obj: web element object to search within.
    Returns:
      web element object with first occurrence of name.
    """
    try:
      self.GetWait().until(EC.presence_of_element_located((By.NAME, name)))
    except TimeoutException:
      self.logger.error('Timed out looking for name: %s', name)
      return None
    else:
      try:
        if obj:
          element = obj.find_element_by_name(name)
        else:
          element = self.driver.find_element_by_name(name)
      except NoSuchElementException:
        self.logger.error('Error finding %s element.', name)
        return None
      return element

  def FindNames(self, name, obj=None):
    """Find web elements using name.

    Args:
      name: string, name to search for.
      obj: web element object to search within.
    Returns:
      list of web element objects containing name.
    """
    try:
      self.GetWait().until(EC.presence_of_all_elements_located((By.NAME, name)))
    except TimeoutException:
      self.logger.error('Timed out finding names: %s', name)
      return None
    else:
      try:
        if obj:
          elements = obj.find_elements_by_name(name)
        else:
          elements = self.driver.find_elements_by_name(name)
      except NoSuchElementException:
        self.logger.error('Error finding name: %s', name)
        return None
      return elements

  def FindTags(self, tagname, obj=None):
    """Find web elements using tagname.

    Args:
      tagname: string, tag to search for.
      obj: web element object to search within.
    Returns:
      list of web element objects containing tagname.
    """
    try:
      self.GetWait().until(EC.presence_of_all_elements_located((By.TAG_NAME,
                                                           tagname)))
    except TimeoutException:
      self.logger.error('Timed out finding names: %s', tagname)
      return None
    else:
      try:
        if obj:
          elements = obj.find_elements_by_tag_name(tagname)
        else:
          elements = self.driver.find_elements_by_tag_name(tagname)
      except NoSuchElementException:
        self.logger.error('Error finding tag: %s', tagname)
        return None
      return elements

  def FindXPath(self, xpath, obj=None):
    """Find web element using xpath.

    Args:
      xpath: string, xpath to search for.
      obj: web element object to search within.
    Returns:
      web element object containing xpath.
    """
    try:
      self.GetWait().until(EC.presence_of_element_located((By.XPATH, xpath)))
    except TimeoutException:
      self.logger.error('Timed out finding XPath: %s', xpath)
      return None
    else:
      try:
        if obj:
          element = obj.find_element_by_xpath(xpath)
        else:
          element = self.driver.find_element_by_xpath(xpath)
      except NoSuchElementException:
        self.logger.error('Error finding xpath: %s', xpath)
        return None
      return element

  def FindXPaths(self, xpath, obj=None):
    """Find all web elements containing xpath.

    Args:
      xpath: xpath string to search for.
      obj: web element object to search within.
    Returns:
      list of web element objects containing xpath.
    """
    try:
      self.GetWait().until(EC.presence_of_all_elements_located((By.XPATH, xpath)))
    except TimeoutException:
      self.logger.error('Timed out finding XPaths: %s', xpath)
      return None
    else:
      try:
        if obj:
          elements = obj.find_elements_by_xpath(xpath)
        else:
          elements = self.driver.find_elements_by_xpath(xpath)
      except NoSuchElementException:
        self.logger.error('Error finding xpath: %s', xpath)
        return None
      return elements

  def Get(self, url):
    """Jump to the specified url.

    Args:
      url: URL to jump.
    """

    self.driver.get(url)
    self.ActionPerformed()

  def GetWait(self):
    """Get wait object which waits loading the current page.

    Returns:
      WebDriver: wait object which waits loading the current page.
    """
    timeout = self.last_action_time + self.timeout - time.time()
    if 0 > timeout:
      timeout = 0
    wait = WebDriverWait(self.driver, timeout)
    return wait

  def MouseOver(self, obj):
    """Mouse over an element.

    Args:
      obj: web element of object to mouse over.
    Returns:
      boolean: True = moused over, False = errors detected.
    """
    try:
      self.action_chain.move_to_element(obj).perform()
    except WebDriverException:
      self.logger.error('Error mousing over element.')
      return False
    finally:
      self.ActionPerformed()
    return True

  def SendKeys(self, keys, obj):
    """Send keys to a web element object.

    Args:
      keys: string, keys to send to object.
      obj: web object to send string to.
    Returns:
      boolean: True = keys sent, False = keys not sent.
    """
    try:
      obj.send_keys(keys)
    except WebDriverException:
      self.logger.error('Error sending keys: %s', keys)
      return False
    finally:
      self.ActionPerformed()
    return True

  def SwitchFrame(self, frame, tagname=None):
    """Switch to a different frame in web page.

    Args:
      frame: string, frame to switch to.
      tagname: string, name of iframe tag.
    Returns:
      boolean: True = frame switched, False = frame not switched.
    """
    try:
      if tagname:
        self.GetWait().until(EC.frame_to_be_available_and_switch_to_it(
            self.driver.find_element_by_tag_name(tagname)))
      else:
        self.GetWait().until(EC.frame_to_be_available_and_switch_to_it(frame))
    except TimeoutException:
      self.logger.error('Timed out finding frame: %s', frame)
      return False
    except NoSuchFrameException:
      self.logger.warning('Frame named %s not found.', frame)
      return False
    return True
