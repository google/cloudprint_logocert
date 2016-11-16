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


Model that represents the CloudJobTicket that's used to submit print jobs to the
Google Cloud Print Service /submit interface.

CloudJobTicket will provide methods to set the various fields of a job ticket:
"""

class CloudJobTicket(object):
  """Represents the print job specifications sent to the printer on job submission."""

  def __init__(self, version):
    """Get a reference to a logger object."""
    self.val = {}
    self.val['version'] = version
    self.val['print'] = {}


  def AddColorOption(self, color_type):
    """
      Specify the print job's color scheme

      Args:
        color_type: string, STANDARD_COLOR or STANDARD_MONOCHROME
    """
    self.val['print']['color'] = {'type': color_type}

  def AddCopiesOption(self, num_copies):
    """
      Specify the number of copies to print

      Args:
        num_copies: integer, number of copies to print
    """
    self.val['print']['copies'] = {'copies': num_copies}

  def AddDuplexOption(self, duplex_type):
    """
      Specify the duplexing type of the print job

      Args:
        duplex_type: string, NO_DUPLEX, LONG_EDGE, or SHORT_EDGE
    """
    self.val['print']['duplex'] = {'type': duplex_type}

  def AddPageOrientationOption(self, orientation_type):
    """
      Specify the page orientation of the print job

      Args:
        orientation_type: string, PORTRAIT, LANDSCAPE, or AUTO
    """
    self.val['print']['page_orientation'] = {'type': orientation_type}

  def AddDpiOption(self, horizontal_dpi, vertical_dpi):
    """
      Specify the DPI for the print job

      Args:
        horizontal_dpi: integer, horizontal dpi
        vertical_dpi  : integer, vertical dpi
    """
    self.val['print']['dpi'] = {'horizontal_dpi': horizontal_dpi,
                                'vertical_dpi': vertical_dpi}

  def AddSizeOption(self, height_microns, width_microns):
    """
      Specify the size of the print job

      Args:
        height_microns: integer, height in microns
        width_microns : integer, width in microns
    """
    self.val['print']['media_size'] = {'height_microns': height_microns,
                                       'width_microns': width_microns}

  def AddReverseOption(self):
    """
      Enable the reverse print option
    """
    self.val['print']['reverse_order'] = {'reverse_order': True}

  def AddFitToPageOption(self, type):
    """
      Specify the size of the print job

      Args:
        type: string, NO_FITTING, FIT_TO_PAGE, GROW_TO_PAGE, SHRINK_TO_PAGE, or FILL_PAGE
    """
    self.val['print']['fit_to_page'] = {'type': type}

  def AddPageRangeOption(self, start, end = None):
    """
      Specify a range of pages to print

      Args:
        start: integer, Beginning of the print interval (inclusive)
        end  : integer, The last page of the range to print (inclusive).
                        If not specified, all pages after 'start' are printed
    """
    # If this is the first page range for this CJT, start with an empty array;
    # otherwise, get the existing array
    page_ranges = [] if 'page_range' not in self.val['print'] else self.val['print']['page_range']['interval']

    new_range = {'start': start}
    if end is not None:
      new_range['end']= end

    page_ranges.append(new_range)

    self.val['print']['page_range']= {'interval': page_ranges}



class CjtConstants(object):
  """A class that holds constants for used in a CJT"""

  # Color scheme
  MONOCHROME = 'STANDARD_MONOCHROME'
  COLOR = 'STANDARD_COLOR'

  # Page orientation
  LANDSCAPE = 'LANDSCAPE'
  PORTRAIT = 'PORTRAIT'

  # Duplexing
  LONG_EDGE = 'LONG_EDGE'
  SHORT_EDGE = 'SHORT_EDGE'

  # Page fit
  NO_FIT = 'NO_FITTING'
  FIT = 'FIT_TO_PAGE'
  GROW = 'GROW_TO_PAGE'
  SHRINK = 'SHRINK_TO_PAGE'
  FILL = 'FILL_PAGE'

  # A4 size in microns
  A4_HEIGHT = 297000
  A4_WIDTH = 210000

  # Printer state
  DRAFT = 'DRAFT'
  HELD = 'HELD'
  QUEUED = 'QUEUED'
  IN_PROGRESS = 'IN_PROGRESS'
  STOPPED = 'STOPPED'
  DONE = 'DONE'
  ABORTED = 'ABORTED'
  ERROR = 'ERROR'