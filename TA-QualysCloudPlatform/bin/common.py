__author__ = "Bharat Patel <bharrat@gmail.com>"
__copyright__ = "Copyright (C) 2014, Bharat Patel"
__license__ = "New BSD"
__version__ = "1.0"
import os
from datetime import datetime
from six.moves.configparser import SafeConfigParser
import qualys.qualys_log_populator
import logging
from qualys import qlogger
from io import open
from six.moves import input

APP_ROOT = os.path.dirname(os.path.realpath(__file__))
config_file = APP_ROOT + '/config/.qsprc'
temp_directory = APP_ROOT + '/tmp'
log_output_directory = ''

default_settings = dict(api_server='https://qualysapi.qualys.com',
                        username='',
                        password='',
                        log_output_directory='',
                        temp_directory='/tmp',
                        log_host_summary='True',
                        log_vuln_detections='True',
                        extra_host_summary='True',
                        minimum_qid='0',
                        truncation_limit='5000',
                        preserve_api_output='False',
                        host_summary_fields='ID,IP,TRACKING_METHOD,DNS,NETBIOS,OS,LAST_SCAN_DATETIME',
                        detection_fields='QID,TYPE,PORT,PROTOCOL,SSL,STATUS,LAST_UPDATE_DATETIME,LAST_FOUND_DATETIME',
                        log_host_details_in_detections='False',
                        detection_params='{"status":"New,Active,Fixed,Re-Opened"}')

start_time = datetime.now()
config = SafeConfigParser(default_settings)


def get_config(key):
    return config.get('QUALYS', key)


def set_config(key, value):
    config.set('QUALYS', key, str(value))


def save_config():
    """
    Write setting file to disk
    """
    # Writing our configuration file to 'example.cfg'
    with open(config_file, 'wb') as configfile:
        config.write(configfile)


class StandaloneQualysLogPopulator(qualys.qualys_log_populator.QualysBaseLogPopulator):

    def get_app_setting(self, key):
        return get_config(key)

    def save_app_setting(self, key, value):
        set_config(key, value)


    def save_settings(self):
        save_config()

    def run(self, api_user=None, api_password=None, configuration_dict=None):
        """


        :type configuration_dict: dict
        :param api_user:
        :param api_password:
        :param configuration_dict:
        """

        qlogger.info("Start")
        if not configuration_dict:
            configuration_dict = {}

        # Merge passed settings with Default APP settings
        configuration_dict = dict(default_settings.items + list(configuration_dict.items()))
        log_output_directory = configuration_dict.get('log_output_directory', None)
        if log_output_directory != '' and os.path.isdir(log_output_directory) and os.access(
                log_output_directory, os.W_OK):
            pass
        else:
            del configuration_dict['log_output_directory']


if not config.has_section('QUALYS'):
    config.add_section('QUALYS')

try:
    with open(config_file) as fp:
        config.readfp(fp)
except IOError as e:
    pass

save_config()

configuration_dict = config._defaults
if 'QUALYS' in config._sections:
    for name in config._sections['QUALYS']:
        configuration_dict[name] = config._sections['QUALYS'][name]

from optparse import OptionParser

parser = OptionParser()
parser.add_option("-o", "--log-output-directory", dest="output_directory",
                  help="Directory for log output, by default logs will be printed to stdout", metavar="DIR")
parser.add_option("-k", "--log-knowledgebase",
                  action="store_true", dest="log_knowledgebase_api", default=False,
                  help="Whether or not to fetch and log output of knowledgebase API")
parser.add_option("-a", "--log-all-qids",
                  action="store_true", dest="log_all_qids", default=False,
                  help="Ignore saved config and log all qids (only applicable with -k option)s")

parser.add_option("-u", "--username", dest="username", help="QualysGuard Username")
parser.add_option("-p", "--password", dest="password", help="QualysGuard Password")
parser.add_option("-s", "--api-server", dest="api_server", help="QualysGuard API Server")

parser.add_option("-d", "--log-detections-api",
                  action="store_true", dest="log_detection_api", default=False,
                  help="Whether or not to fetch and log output of detection API")
parser.add_option("-D", "--debug",
                  action="store_true", dest="debug", default=False,
                  help="Enable debug")

(options, args) = parser.parse_args()
if options.debug:
    qlogger.setLevel(logging.DEBUG)

api_user = config.get('QUALYS', 'username')
api_password = config.get('QUALYS', 'password')
api_server = None

if options.username:
    api_user = options.username
if options.password:
    api_password = options.password

if options.api_server:
    api_server = options.api_server
    configuration_dict['api_server'] = api_server
if options.output_directory:
    configuration_dict['log_output_directory'] = options.output_directory

if api_user is None or api_user == '':
    api_user = input("QG Username:")

if api_password is None or api_password == '':
    import getpass

    api_password = getpass.getpass("QG Password:")

if options.log_all_qids:
    configuration_dict['minimum_qid'] = 0
