# -*- coding: utf-8 -*-
"""This script will handle custom alerts raised for WAS scanning"""

# Standard imports
from __future__ import print_function

__author__ = "Prabhas Gupte"
__copyright__ = "Copyright (C) 2016, Qualys, Inc."
__license__ = "New BSD"
__version__ = "1.0"

# Standard imports
import sys
import json
import csv
import gzip
import logging
import logging.handlers

from defusedxml import ElementTree as ET

# Splunk related imports
import splunk.entity as entity
import splunk.clilib.cli_common as scc
try:
    from splunk.clilib.bundle_paths import make_splunkhome_path
except ImportError:
    from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

sys.path.append(make_splunkhome_path(["etc", "apps", "Splunk_SA_CIM", "lib"]))
sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))

from cim_actions import ModularAction

# TA related imports
import qualysModule
import qualysModule.lib.api as qapi
import qualysModule.splunkpopulator.utils
from qualysModule.splunkpopulator.utils import get_password

API_ENDPOINT = '/qps/rest/3.0/update/was/webapp/'

# set the maximum allowable CSV field size
#
# The default of the csv module is 128KB; upping to 10MB. See SPL-12117 for
# the background on issues surrounding field sizes.
# (this method is new in python 2.5)
csv.field_size_limit(10485760)

def setup_logger():
    """
    Setup a logger for the REST handler.
    """

    logger = logging.getLogger('qualys_modaction')
    logger.setLevel(logging.INFO)

    file_handler = logging.handlers.RotatingFileHandler(
        make_splunkhome_path(['var', 'log', 'splunk', 'qualys_modalert.log']),
        maxBytes=25000000, backupCount=5)
    formatter = logging.Formatter('%(asctime)s %(lineno)d %(levelname)s %(message)s')
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger
# end of setup_logger

logger = setup_logger()

# ModularAction wrapper class
class QualysTagWebappModularAction(ModularAction):
    def __init__(self, settings, logger, action_name=None):
        super(QualysTagWebappModularAction, self).__init__(settings, logger, action_name)
        self.tag_ids = self.configuration.get('tag_ids', '')
        self.logger.info("Tag IDs = %s", self.tag_ids)
    # __init__

    def add_event(self, events):
        if modaction.makeevents(events, index="main", source="qualys", sourcetype="apply_qualys_tag_to_webapp_action"):
            logger.info("Created Splunk event for QualysTagWebappModularAction.")
        else:
            logger.critical("Failed creating Splunk event for QualysTagWebappModularAction.")
        # if-else
        return
    # end of add_event

    def get_api_params(self, tag_ids):
        tag_str = ""
        for tag_id in tag_ids:
            tag_str = tag_str + "<Tag><id>%s</id></Tag>" % tag_id.strip()
        # for

        params = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?><ServiceRequest><data><WebApp><tags><add>%s</add></tags></WebApp></data></ServiceRequest>"

        return params % tag_str
    # end of get_api_params

    def apply_tag(self, session_key, result):
        '''
        This function will make the actual API call to launch the WAS scan.
        '''
        # print >> sys.stderr, "INFO Launching WAS scan with settings: %s" % settings

        # get API server, user and password
        api_user, api_password = qualysModule.splunkpopulator.utils.getCredentials(session_key)
        qualys_conf = scc.getMergedConf('qualys')
        api_server = qualys_conf['setupentity']['api_server']
        use_proxy = qualys_conf['setupentity']['use_proxy']
        proxy = qualys_conf['setupentity']['proxy_server']
        retry_interval = qualys_conf['setupentity']['retry_interval_seconds']
        api_timeout = qualys_conf['setupentity']['api_timeout']
        use_ca = qualys_conf['setupentity']['use_ca']

        if api_user is None or api_user == '' or \
                api_password is None or api_password == '' or \
                api_server is None or api_server == '':
            logger.info("API server/username/password not configured. Exiting.")
            # self.add_event(["API server/username/password not configured. Exiting."])
            self.addevent("API server/username/password not configured. Exiting.", self.action_name)
            exit(3)

        api_config = qapi.Client.APIConfig()
        api_config.username = api_user
        api_config.password = api_password
        api_config.serverRoot = api_server
        api_config.retry_interval = retry_interval 
        api_config.api_timeout = api_timeout
        
        api_config.use_ca, api_config.ca_path, api_config.ca_key, api_config.ca_pass = None, None, None, None
        if use_ca == '1':
            ca_path = qualys_conf['setupentity']['ca_path']
            ca_key = qualysConf['setupentity']['ca_key']
            ca_pass = get_password(session_key, "qualys_ca_passphrase", "TA-QualysCloudPlatform")
            apiConfig.use_ca = True
            apiConfig.ca_path, apiConfig.ca_key, apiConfig.ca_pass = ca_path,  ca_key or None, ca_pass or None

        if use_proxy == '1':
            api_config.useProxy = True
            api_config.proxyHost = proxy

        ta_version = "Unidentified"
        appConf = scc.getAppConf("app", "TA-QualysCloudPlatform")
        ta_version = appConf['launcher']['version']
        api_config.ta_version = ta_version
        
        qapi.setupClient(api_config)
        api_client = qapi.client

        webapp_id_in_result = result.get('webapp_id', None)

        tag_ids = self.tag_ids.split(",")
        logger.info("Tag ID(s) to apply: %s" % tag_ids)
        api_params = self.get_api_params(tag_ids)
        logger.info("Parameters to apply tag: %s" % api_params)
        self.addevent("Making %s request with params %s" % (API_ENDPOINT + webapp_id_in_result, api_params), self.action_name)
        response = api_client.get(API_ENDPOINT + webapp_id_in_result, api_params, qapi.Client.SimpleAPIResponse())
        api_response = response.get_response()
        logger.info("API response is %s" % api_response)
        response_root = ET.fromstring(api_response)
        response_code = response_root.find('responseCode').text
        self.addevent("API response is %s" % response_code, self.action_name)
        if response_code == "SUCCESS":
            self.addevent("Successfully applied tag id(s) %s to webapp id %s" % (self.tag_ids, webapp_id_in_result), self.action_name)
            return True
        else:
            self.addevent("Could not apply tag id(s) %s to webapp id %s" % (self.tag_ids, webapp_id_in_result), self.action_name)
            return False
    # end of apply_tag

# end of class QualysTagWebappModularAction

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "--execute":
        logger.error("FATAL Unsupported execution mode. (expected --execute flag)")
        sys.exit(1)

    try:
        modaction = QualysTagWebappModularAction(sys.stdin.read(), logger, 'apply_qualys_tag_to_webapp')
        session_key = modaction.session_key
        if logger.isEnabledFor(logging.DEBUG):
            temp_modaction = modaction.settings
            temp_modaction.pop("session_key")
            logger.debug("%s", json.dumps(temp_modaction, sort_keys=True, indent=4, separators=(',', ': ')))
            modaction.addevent("Settings are: %s" % json.dumps(temp_modaction, sort_keys=True, indent=4, separators=(',', ': ')), modaction.action_name)
        # process results
        
        with gzip.open(modaction.results_file, 'rt') as fh:
            modaction.addevent("Processing result file %s" % modaction.results_file, modaction.action_name)
            for num, result in enumerate(csv.DictReader(fh)):
                num_str = str(num)
                modaction.addevent("Processing result row %s" % num_str, modaction.action_name)
                # set rid to row number (0->n) if unset
                result.setdefault('rid', num_str)
                modaction.update(result)
                modaction.invoke()
                successful = modaction.apply_tag(session_key, result)
            # for
            modaction.addevent("Done processing result file %s" % modaction.results_file, modaction.action_name)
        # with
        if modaction.writeevents(index='main',source=modaction.search_name):
            modaction.message('Successfully created splunk event', status='success', rids=modaction.rids)
        else:
            modaction.message('Failed to create splunk event', status='failure',rids=modaction.rids, level=logging.ERROR)
        # if-else
    except Exception as e:
        try:
            logger.critical(modaction.message(e, "failure"))
        except:
            logger.critical(e)
        logger.error("ERROR Unexpected error: %s" % e)
        sys.exit(3)
# end of if main
