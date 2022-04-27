from __future__ import print_function

# -*- coding: utf-8 -*-
__author__ = "Bharat Patel <bharrat@gmail.com>"
__copyright__ = "Copyright (C) 2014, Bharat Patel"
__license__ = "New BSD"
__version__ = "1.0"
__APP_NAME = 'Qualys Splunk Populator'

import sys
import os
from datetime import datetime
import logging
try:
    from splunk.clilib.bundle_paths import make_splunkhome_path
except ImportError:
    from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

start_time = datetime.now()

# create logger
qlogger = logging.getLogger('TA-QualysCloudPlatform')

debug = False


def enableDebug(on):
    global debug
    debug = on


formatter = logging.Formatter('%(name)s: %(asctime)s PID=%(process)s [%(threadName)s] %(levelname)s: %(message)s', "%Y-%m-%d %H:%M:%S")

# create console handler and set level to debug
#ch = logging.FileHandler('%s/qualys_%s.log' % (temp_directory, start_time.strftime('%Y-%m-%d')))
#ch.setLevel(logging.DEBUG)
#ch.setFormatter(formatter)
# qlogger.addHandler(ch)

def enableLogger():
    global debug, qlogger

    fh = logging.handlers.RotatingFileHandler(
        make_splunkhome_path(['var', 'log', 'splunk', 'ta_QualysCloudPlatform.log']),
        maxBytes=25000000, backupCount=5)
    fh.setFormatter(formatter)

    if debug:
        qlogger.setLevel(logging.DEBUG)
        fh.setLevel(logging.DEBUG)
    else:
        qlogger.setLevel(logging.INFO)
        fh.setLevel(logging.INFO)

    debug_log_handler = logging.StreamHandler(sys.stdout)
    debug_log_handler.setFormatter(formatter)



    qlogger.addHandler(debug_log_handler)
    qlogger.addHandler(fh)


APP_ROOT = os.path.abspath(os.path.dirname(sys.argv[0]) + '/')
# config_file = APP_ROOT + '/../config/.qsprc'
temp_directory = APP_ROOT + '/../tmp'
log_output_directory = ''
TA_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
