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


Function to provide a logger that writes to stdout, memory, and files.

Logger objects are used to control how and when messages are logged. This
function will perform some general housekeeping and organization. It will also
existing loggers don't get extra handlers added to them if this code is called
multiple times.
"""

import logging
import os
from StringIO import StringIO
import sys
import time


def GetLogger(name, logdir=None, loglevel='info', stdout=False):
  """Return a new logger, or reference to an existing logger.

  Args:
    name: string, name of logger.
    logdir: string, path to a directly to place log files.
    loglevel: string, debug level of logger.
    stdout: boolean, True = send messages to stdout and logfile.
                     False = only send messages to log file.
  Returns:
    initialized logger.

  Since Python loggers are a singleton, logging.getLogger() will always return
  a reference to the current logger with identical names. This function uses
  3 handlers, so if handlers == 0 the logger requires proper configuration
  of handlers and log files.
  """
  logger = logging.getLogger(name)
  if not logger.handlers:
    datetime_str = time.strftime('%Y%B%d_%H%M%S', time.localtime())
    log_filename = '%s%s%s' % (name, datetime_str, '.log')
    if not logdir:
      logdir = '/tmp/logfiles'
    if not os.path.isdir(logdir):
      try:
        os.makedirs(logdir)
      except IOError:
        print 'Error creating log directory!'
        sys.exit(1)

    logfile = os.path.join(logdir, log_filename)
    strlog = StringIO()

    c = logging.StreamHandler()
    s = logging.StreamHandler(strlog)
    h = logging.FileHandler(logfile)
    hf = logging.Formatter('%(asctime)s, %(name)s %(levelname)s: %(message)s')
    cf = logging.Formatter('%(name)s %(levelname)s: %(message)s')
    sf = logging.Formatter('%(name)s %(levelname)s: %(message)s')
    logger.addHandler(h)
    logger.addHandler(s)
    h.setFormatter(hf)
    s.setFormatter(sf)
    if stdout:
      logger.addHandler(c)
      c.setFormatter(cf)

    levels = {'debug': logging.DEBUG,
              'info': logging.INFO,
              'warning': logging.WARNING,
              'error': logging.ERROR,
              'critical': logging.CRITICAL,
             }
    logger.setLevel(levels.get(loglevel, logging.INFO))
    logger.debug(
        'Invocation started. Logger %s\nLogger Name: %s\nLog Mode: %s',
        logfile, name, loglevel)
  else:
    logger.debug('Logger %s is already initialized', name)

  return logger

