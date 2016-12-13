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


Support for mdns operations.

This module will provide a class to browse MDNS messages on the local network.
It depends on the Python package zeroconf.

The main interface to this module are the wait_for_privet_mdns_service and
mdns_privet_device functions.  The _Listener class is intended for the internals
of this module and users of this module do not directly need to use it.
"""
import copy
import threading
import time
import zeroconf
from zeroconf import ServiceBrowser
from zeroconf import Zeroconf


class _Listener(object):
  """Helper class for this module.

  Used to provide threadsafe recording of found mDNS services.  This is required
  since Zeroconf's ServiceBrowser class spawns a thread.
  Use the services() function to read known services.
  """

  def __init__(self, logger):
    self._added_service_infos = []
    self._removed_service_names = []
    self.lock = threading.Lock()
    self.logger = logger

  def remove_service(self, zeroconf_obj, service_type, name):
    self.logger.info('Service removed: "%s" (type is %s)', name, service_type)
    self.lock.acquire()
    self._removed_service_names.append(name)
    self.lock.release()
    pass

  def add_service(self, zeroconf_obj, service_type, name):
    """Callback called by ServiceBrowser when a new mDNS service is discovered.

    Sometimes there is a delay in zeroconf between the add_service callback
    being triggered and the service actually being returned in a call to
    zeroconf_obj.get_service_info().  Because of this there are a few retries.
    Args:
      zeroconf_obj: The Zeroconf class instance.
      service_type: The string name of the service, such
        as '_privet._tcp.local.'.
      name: The name of the service on mDNS.
    """
    self.logger.info('Service added: "%s" (type is %s)', name, service_type)
    self.lock.acquire()
    info = zeroconf_obj.get_service_info(service_type, name, timeout=10000)
    retries = 5
    while info is None and retries > 0:
      self.logger.error('zeroconf_obj.get_service_info returned None, forces '
                        'retry.')
      time.sleep(0.1)
      retries -= 1
      info = zeroconf_obj.get_service_info(service_type, name, timeout=10000)
    if info is not None:
      self._added_service_infos.append(copy.deepcopy(info))
    self.lock.release()

  def services(self):
    self.lock.acquire()
    infos = copy.deepcopy(self._added_service_infos)
    self.lock.release()
    return infos

  def removed_services(self):
    self.lock.acquire()
    removed_service_names = copy.deepcopy(self._removed_service_names)
    self.lock.release()
    return removed_service_names


def _find_zeroconf_threads():
  """Find all living threads that were started by zeroconf.

  Returns:
    List of thread objects started by zeroconf that are currently alive
    according to threading.enumerate().
  """
  def is_zeroconf_thread(thread):
    zeroconf_thread_objs = [
        zeroconf.Engine,
        zeroconf.Reaper,
        zeroconf.ServiceBrowser
    ]
    for obj in zeroconf_thread_objs:
      if isinstance(thread, obj):
        return True
    return False
  zeroconf_threads = filter(is_zeroconf_thread, threading.enumerate())
  return zeroconf_threads


# pylint: disable=dangerous-default-value
# The default case, [] is explicitly handled, and common.
def wait_for_privet_mdns_service(t_seconds, service, logger, wifi_interfaces=[]):
  """Listens for t_seconds and returns an information object for each service.

  This is the primary interface to discover mDNS services.  It blocks for
  t_seconds while listening, and returns a list of information objects, one
  for each service discovered.
  Args:
    t_seconds: Time to listen for mDNS records, in seconds.  Floating point ok.
    service: The service to wait for, if found, return early
    is_add: If True, wait for service to be added - If False, wait for service to be removed
    wifi_interfaces: The interfaces to listen on as strings, if empty listen on
      all interfaces.  For example: ['192.168.1.2'].
  Returns:
    If Add event observed, return the Zeroconf information class; otherwise, return None
  """
  l = _Listener(logger)
  if not wifi_interfaces:
    z = Zeroconf()
  else:
    z = Zeroconf(wifi_interfaces)
  sb = ServiceBrowser(zc=z, type_='_privet._tcp.local.', listener=l)

  service_info = wait_for_service_add(t_seconds, service, l)

  sb.cancel()
  z._GLOBAL_DONE = True  # Only method available to kill all threads pylint: disable=protected-access
  zeroconf_threads = _find_zeroconf_threads()
  while len(zeroconf_threads) > 1:
    time.sleep(0.01)
    zeroconf_threads = _find_zeroconf_threads()
  z.close()
  logger.info('All listeners have been stopped.')
  return service_info
# pylint: enable=dangerous-default-value


def wait_for_service_add(t_seconds, target_service, listener):
  """Wait for a service to be added.

      Args:
        t_seconds: Time to listen for mDNS records, in seconds.  Floating point ok.
        service: string, The service to wait for, if found, return early
        listener: _Listener object, the listener to wait on
      Returns:
        If Add event observed, return the Zeroconf information class; otherwise, return None
    """
  t_end = time.time() + t_seconds
  while time.time() < t_end:
    services = listener.services()
    for service in services:
      if target_service in service.properties['ty']:
        return service
    time.sleep(1)
  return None


class MDNS_Browser:
  """Public class for this module.

    Used for keeping the service browser running until the user decides to stop it
    """
  def __init__(self, logger, wifi_interfaces=[]):
    """Initialization requires a logger.

    Args:
      logger: initialized logger object.
      if_addr: string, interface address for Zeroconf, None means all interfaces.
    """
    self.logger = logger
    self.l = _Listener(logger)
    if not wifi_interfaces:
      self.z = Zeroconf()
    else:
      self.z = Zeroconf(wifi_interfaces)
    self.sb = ServiceBrowser(zc=self.z, type_='_privet._tcp.local.', listener=self.l)

  def Wait_for_service_add(self, t_seconds, target_service):
    """Wait for a service to be added.

            Args:
              t_seconds: Time to listen for mDNS records, in seconds.  Floating point ok.
              service: string, The service to wait for, if found, return early
            Returns:
              If Add event observed, return the Zeroconf information class; otherwise, return None
          """
    return wait_for_service_add(t_seconds, target_service, self.l)

  def Wait_for_service_remove(self, t_seconds, target_service):
    """Wait for a service to be removed.

        Args:
          t_seconds: Time to listen for mDNS records, in seconds.  Floating point ok.
          service: string, The service to wait for, if found, return early
        Returns:
          If Remove event observed, return the True; otherwise, return False
      """
    t_end = time.time() + t_seconds
    while time.time() < t_end:
      services = self.l.removed_services()
      for service in services:
        if target_service in service:
          return True
      time.sleep(1)
    return False

  def Close(self):
    """Terminate the MDNS listening session by joining all threads"""
    self.sb.cancel()
    self.z._GLOBAL_DONE = True  # Only method available to kill all threads pylint: disable=protected-access
    zeroconf_threads = _find_zeroconf_threads()
    while len(zeroconf_threads) > 1:
      time.sleep(0.01)
      zeroconf_threads = _find_zeroconf_threads()
      self.z.close()
    self.logger.info('All listeners have been stopped.')
    return

  def Get_service_ttl(self, name):
    """Get the printer service's DNS record's TTL

    Args:
      name: String, name of the service to get the TTL for.
    Returns:
          integer, TTL if service is found, None otherwise.
    """
    for service in self.l.services():
      service_name = service.name.lower()
      if service_name.startswith(name.lower()):
        return self.sb.services[service_name].get_remaining_ttl(time.time()* 1000)
    return None