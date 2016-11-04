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


class MDnsService(object):
  """A MDNS Service.

  Note that in this case the methods must be named exactly as they are, as the
  ServiceBrowser from zeroconf will require those method names from it's
  listener.
  """

  def __init__(self, logger):
    """Initialization requires a logger.
    
    Args:
      logger: initialized logger object.
    """
    self.logger = logger
    self.discovered = {}

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

  def remove_service(self, zeroconf, service_type, name):
    self.discovered[name]['found'] = False
    self.logger.info('Service removed: %s', name)
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

    ServiceBrowser(self.zeroconf, protocols[proto], self.listener)
    self.logger.info('Browsing for %s services...', proto)
    return True

  def remove_listeners(self):
    """Remove all listeners."""
    self.zeroconf.close()
    self.logger.info('All listeners have been stopped.')
