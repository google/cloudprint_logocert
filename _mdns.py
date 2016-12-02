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
"""
from zeroconf import InterfaceChoice
from zeroconf import ServiceBrowser
from zeroconf import Zeroconf
from zeroconf import DNSCache
import time
from Queue import Queue

class MDnsService(object):
  """A MDNS Service.

  Note that in this case the methods must be named exactly as they are, as the
  ServiceBrowser from zeroconf will require those method names from its
  listener.
  """

  def __init__(self, logger):
    """Initialization requires a logger.
    
    Args:
      logger: initialized logger object.
    """
    self.logger = logger
    self.discovered = {}

    # Queues of tuples - (device name, timestamp of addition/removal) 
    # Helps keep track of the services that have been added or removed
    # Useful for signalling printer's on/off status
    self.added_q = Queue()
    self.removed_q = Queue()

  # pylint: disable=unused-argument
  def add_service(self, zeroconf, service_type, name):
    self.logger.info('Service added: "%s" (type is %s)', name, service_type)
    self.discovered[name] = {}
    self.discovered[name]['proto'] = service_type
    self.discovered[name]['found'] = True

    info = zeroconf.get_service_info(service_type, name)
    if info:
      self.discovered[name]['info'] = info
      self.logger.debug('%s service info: %s', name, info)
    else:
      self.logger.debug('Service has no info.')
    self.added_q.put((name, time.time()))


  def remove_service(self, zeroconf, service_type, name):
    self.discovered[name]['found'] = False
    self.logger.info('Service removed: %s', name)
    self.removed_q.put((name, time.time()))
  # pylint: enable=unused-argument


class MDnsListener(object):
  """A MDNS Listener."""

  def __init__(self, logger, if_addr=None):
    """Initialization requires a logger.
    
    Args:
      logger: initialized logger object.
      if_addr: string, interface address for Zeroconf, None means all interfaces.
    """
    # self.logger = _log.GetLogger('LogoCert')
    self.logger = logger
    if if_addr:
      self.zeroconf = Zeroconf([if_addr])
    else:
      self.zeroconf = Zeroconf(InterfaceChoice.All)
    self.listener = MDnsService(logger)
    self.sb = None

  def add_listener(self, proto):
    """Browse for announcements of a particular protocol.

    Args:
      proto: string, type of traffic to listen for.
    Returns:
      boolean, True = browser activated, False = errors detected.
    """
    protocols = {'http': '_http._tcp.local.',
                 'ipp': '_ipp._tcp.local.',
                 'mdns': '_mdns._udp.local.',
                 'printer': '_printer._tcp.local.',
                 'privet': '_privet._tcp.local.',
                }

    if proto not in protocols:
      self.logger.error('Error starting listener, %s protocol unkown', proto)
      return False

    self.sb = ServiceBrowser(self.zeroconf, protocols[proto], self.listener)
    self.logger.info('Browsing for %s services...', proto)
    return True

  def remove_service_entry(self, name):
    """Remove a service entry from the ServiceBrowser

        Args:
          name: string, the service to remove.
        Returns:
          boolean, True = serice removed, False = service not found.
        """
    for service in self.sb.services:
      if name.lower() in service.lower():
        self.clear_cache()
        self.logger.info('Service removed: '+service)
        del(self.sb.services[service])
        return True
    return False

  def remove_listeners(self):
    """Remove all listeners."""
    self.zeroconf.close()
    self.logger.info('All listeners have been stopped.')

  def clear_cache(self):
    """Remove all cached entries"""
    self.zeroconf.cache = DNSCache()

  def get_added_q(self):
    """Return a queue of added services"""
    return self.listener.added_q

  def get_removed_q(self):
    """Return a queue of removed services"""
    return self.listener.removed_q