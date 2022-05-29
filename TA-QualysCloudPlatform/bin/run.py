#!/usr/bin/python

# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "Qualys Inc."
__copyright__ = "Copyright (C) 2019, Qualys"
__license__ = "New BSD"
__version__ = "1.0"

import time
import sys, os

# dynamically load all the .whl files
TA_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
WHL_DIR = TA_ROOT + "/bin/whl/"
for filename in os.listdir(WHL_DIR):
	if filename.endswith(".whl"):
		sys.path.insert(0, WHL_DIR + filename)

import re
from datetime import datetime, timedelta
import traceback
import logging
import fcntl, sys
import json
from six.moves.urllib.parse import urlparse
from io import open

from defusedxml import ElementTree as ET

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import splunk.clilib.cli_common as scc

from lib.splunklib.modularinput import *
import qualysModule.qualys_log_populator
import qualysModule.splunkpopulator.utils
from qualysModule.application_configuration import *
from qualysModule import qlogger
import qualysModule.lib.api as qapi


#CONSTANTS
SERVICES_BEHIND_GATEWAY = ['fim_events', 'fim_ignored_events', 'fim_incidents', 'edr_events','cs_container_vulns','cs_image_vulns','sem_detection','pcrs_posture_info']
#qualys_platforms_url_map is a map of urls not having 'apps' in url; new pods apis are having apps in name
#e.g. https://qualysapi.qg1.apps.qualys.in, https://qualysapi.qg2.apps.qualys.eu
QUALYS_PLATFORMS_URLS_NOT_HAVING_apps = {
	"https://gateway.qg1.apps.qualys.com": "https://qualysapi.qualys.com",
	"https://gateway.qg1.apps.qualys.eu": "https://qualysapi.qualys.eu"
}

data_input_running = ""
pid_file = APP_ROOT + '/run.pid'
fp = None
try:
	fp = open(pid_file, 'w')
	fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
except IOError as e:
	# another instance is running
	if fp:
		sys.stderr.write('Another instance of run.py already running. PID=%s' % os.getpid())
		fp.close()
	else:
		qlogger.error(e)	
	sys.exit(0)
finally:
	fp and fp.close()

parser = OptionParser()

parser.add_option("-c", "--compliance-posture-info",
					action="store_true", dest="log_pc_api", default=False,
					help="Log Policy Compliance Posture Information entries")

parser.add_option("--pcrs", "--compliance-pcrs-info",
					action="store_true", dest="log_pcrs_api", default=False,
					help="Log PCRS Posture Information entries")

parser.add_option("-k", "--log-knowledgebase",
					action="store_true", dest="log_kb_api", default=False,
					help="Log knowledgebase entries")

parser.add_option("-d", "--log-host-detections",
					action="store_true", dest="log_detection_api", default=False,
					help="Log Host detections")

parser.add_option("-w", "--log-was-findings",
					action="store_true", dest="log_findings_api", default=False,
					help="Log WAS findings")
					
parser.add_option("--csi", "--log-csi-info",
					action="store_true", dest="log_csi_api", default=False,
					help="Log CS image info")

parser.add_option("--csc", "--log-csc-info",
					action="store_true", dest="log_csc_api", default=False,
					help="Log CS container info")

parser.add_option("--fe", "--log-fim-events",
					action="store_true", dest="log_fim_events_api", default=False,
					help="Log FIM events")

parser.add_option("--fie", "--log-fim-ignored-events",
					action="store_true", dest="log_fim_ignored_events_api", default=False,
					help="Log FIM Ignored events")

parser.add_option("--fi", "--log-fim-incidents",
					action="store_true", dest="log_fim_incidents_api", default=False,
					help="Log FIM incidents")

parser.add_option("--edr", "--log-edr",
					action="store_true", dest="log_edr_api", default=False,
					help="Log EDR Events")

parser.add_option("--al", "--log-activity-log",
					action="store_true", dest="log_activity_log_api", default=False,
					help="Log Activity Log")
                    
parser.add_option("--sem", "--log-sem-detection",
					action="store_true", dest="log_sem_api", default=False,
					help="Log Activity Log")

parser.add_option("-s", "--api-server",
					dest="api_server", default="https://qualysapi.qualys.com",
					help="API Server URL")

parser.add_option("-u", "--username",
					dest="username", default=None,
					help="QG Username")

parser.add_option("-p", "--password",
					dest="password", default=None,
					help="QG Password")

parser.add_option("-f", "--from-date",
					dest="start_date", default="1999-01-01T00:00:00Z",
					help="")

parser.add_option("-x", "--proxy",
					dest="proxy_host", default=None,
					help="Proxy address")

parser.add_option("-g", "--debug",
					action="store_true", dest="debug", default=False,
					help="Debug mode")

parser.add_option("--ca-path", "--ca-path",
					dest="ca_path", default=None,
					help="CA certificate file Path")

parser.add_option("--ca-key", "--ca-key",
					dest="ca_key", default=None,
					help="CA certificate key file Path")

parser.add_option("--ca-pass", "--ca-pass",
					dest="ca_pass", default=None,
					help="CA certificate Passphrase")

(options, args) = parser.parse_args()

log_pc_api = False
log_pcrs_api =False
log_kb_api = False
log_detection_api = False
log_findings_api = False
log_csi_api = False
log_csc_api = False
log_fim_events_api = False
log_fim_ignored_events_api = False
log_fim_incidents_api = False
log_edr_api = False
log_activity_log_api = False
log_sem_api = False
log_ids = False
api_server = None
api_user = None
api_password = None
proxy = None
start_date = "1999-01-01T00:00:00Z"

if options.debug:
	qualysModule.enableDebug(True)

qualysModule.enableLogger()

if options.proxy_host:
	proxy = options.proxy_host

if options.log_kb_api:
	log_kb_api = True
	data_input_running = "knowledge_base"

if options.log_detection_api:
	log_detection_api = True
	data_input_running = "host_detection"

if options.log_findings_api:
	log_findings_api = True
	data_input_running = "was_findings"

if options.log_pc_api:
	log_pc_api = True
	data_input_running = "policy_posture_info"

if options.log_pcrs_api:
	log_pcrs_api = True
	data_input_running = "pcrs_posture_info"
	
if options.log_csi_api:
	log_csi_api = True
	data_input_running = "cs_image_vulns"

if options.log_csc_api:
	log_csc_api = True
	data_input_running = "cs_container_vulns"

if options.log_fim_events_api:
	log_fim_events_api = True
	data_input_running = "fim_events"

if options.log_fim_ignored_events_api:
	log_fim_ignored_events_api = True
	data_input_running = "fim_ignored_events"

if options.log_fim_incidents_api:
	log_fim_incidents_api = True
	data_input_running = "fim_incidents"

if options.log_edr_api:
	log_edr_api = True
	data_input_running = "edr_events"

if options.log_activity_log_api:
	log_activity_log_api = True
	data_input_running = "activity_log"

if options.log_sem_api:
	log_sem_api = True
	data_input_running = "sem_detection"

if options.api_server:
	api_server = options.api_server

if options.username:
	api_user = options.username

if options.password:
	api_password = options.password

if options.start_date:
	start_date = options.start_date
	
ca_path = options.ca_path if options.ca_path else None
ca_key = options.ca_key if options.ca_key else None
ca_pass = options.ca_pass if options.ca_pass else None

temp_directory = APP_ROOT + '/tmp'

qualysConf = scc.getMergedConf("qualys")

try:
	appConf = scc.getAppConf("app", "TA-QualysCloudPlatform")
	ta_version = appConf['launcher']['version']
	qlogger.info("Qualys TA version=%s", ta_version)
except Exception as e:
	pass

appConfig = ApplicationConfiguration()
appConfig.load()

if proxy is None:
	proxy = qualysConf['setupentity']['proxy_server']

if api_server is None:
	#if not passed via CLI argument then load from config file
	api_server = qualysConf['setupentity']['api_server']

if api_server is None or api_server == '':
	api_server = input("QG API Server:")

if api_user is None or api_user == '':
	api_user = input("QG Username:")

if api_password is None or api_password == '':
	import getpass
	api_password = getpass.getpass("QG Password:")

# translate gateway and non-gateway API URLs accordingly
if data_input_running in SERVICES_BEHIND_GATEWAY:
	if not api_server.startswith("https://gateway"):
		# make it gateway url
		if api_server in list(QUALYS_PLATFORMS_URLS_NOT_HAVING_apps.values()):
			api_server = re.sub(r"https:\/\/(qualysapi|qualysaguard)", "https://gateway.qg1.apps", api_server)
		else:
			api_server = re.sub(r"https:\/\/(qualysapi|qualysguard)", "https://gateway", api_server)
		qlogger.info("API URL changed to %s for %s data input", api_server, data_input_running)
else:
	# not a gateway service
	if not re.search(r"^https:\/\/(qualysapi|qualysaguard)", api_server):
		# make it api url
		if api_server in QUALYS_PLATFORMS_URLS_NOT_HAVING_apps:
			api_server = QUALYS_PLATFORMS_URLS_NOT_HAVING_apps[api_server]
		else:
			api_server = re.sub(r"https:\/\/gateway", "https://qualysapi", api_server)
		qlogger.info("API URL changed to %s for %s data input", api_server, data_input_running)

apiConfig = qapi.Client.APIConfig()
apiConfig.username = api_user
apiConfig.password = api_password
apiConfig.api_timeout = qualysConf['setupentity']['api_timeout'] if 'api_timeout' in qualysConf['setupentity'] else 300
apiConfig.retry_interval = qualysConf['setupentity']['retry_interval_seconds'] if 'retry_interval_seconds' in qualysConf['setupentity'] else 300
apiConfig.serverRoot = api_server
apiConfig.ta_version = ta_version
apiConfig.proxy_server = proxy

if proxy:
	qlogger.info("Using proxy: %s", proxy)
	apiConfig.useProxy = True
	apiConfig.proxyHost = proxy

if ca_path:
	qlogger.info("Using CA Certificate authentication scheme")
apiConfig.use_ca = True if ca_path else False
apiConfig.ca_path = ca_path if ca_path else None
apiConfig.ca_key = ca_key if ca_key else None
apiConfig.ca_pass = ca_pass if ca_pass else None

# when more data inputs added which are behind gateway=> is_behind_gateway = (log_fim_api or log_edr)
is_behind_gateway = log_fim_events_api or log_fim_ignored_events_api or log_fim_incidents_api or log_edr_api or log_csi_api or log_csc_api or log_sem_api or log_pcrs_api
qapi.setupClient(apiConfig, is_behind_gateway)
qapi.client.validate()
ew = EventWriter()
h = 'localhost'
i = 'main'
print("Running with host '%s' and will use '%s' as index name." % (h, i))
try:
	if log_kb_api:
		cp = './knowledge_base'
		qlogger.info("Running knowledgebase input")
		kbPopulator = qualysModule.qualys_log_populator.QualysKBPopulator(settings=appConfig, checkpoint=cp, host=h, index=i, start_date=start_date)
		kbPopulator.populate_lookup_table = True
		kbPopulator.run()

	if log_detection_api:
		cp = './host_detection'
		qlogger.info("Running host detection input")
		detectionPopulator = qualysModule.qualys_log_populator.QualysDetectionPopulator(settings=appConfig, checkpoint=cp, host=h, index=i, start_date=start_date, event_writer=ew)
		detectionPopulator.run()

	if log_findings_api:
		cp = './was_findings'
		qlogger.info("Running WAS findings input")
		wasFindingsPopulator = qualysModule.qualys_log_populator.QualysWasDetectionPopulator(settings=appConfig, checkpoint=cp, host=h, index=i, start_date=start_date, event_writer=ew)
		wasFindingsPopulator.run()

	if log_pc_api:
		cp = './policy_posture_info'
		qlogger.info("Running PC posture information input")
		pcPosturePopulator = qualysModule.qualys_log_populator.QualysPCPosturePopulator(settings=appConfig, checkpoint=cp, host=h, index=i, start_date=start_date, event_writer=ew)
		pcPosturePopulator.run()

	if log_pcrs_api:
		cp = './pcrs_posture_info'
		qlogger.info("Running PCRS posture information input")
		pcPosturePopulator = qualysModule.qualys_log_populator.QualysPCRSPopulator(settings=appConfig, checkpoint=cp, host=h, index=i, start_date=start_date, event_writer=ew)
		pcPosturePopulator.run()
		
	if log_csi_api:
		cp = './cs_image_vulns'
		qlogger.info("Running CS Images input")
		csImagePopulator = qualysModule.qualys_log_populator.QualysCSImagePopulator(settings=appConfig, checkpoint=cp, host=h, index=i, start_date=start_date, event_writer=ew)
		csImagePopulator.run()

	if log_csc_api:
		cp = './cs_container_vulns'
		qlogger.info("Running CS Containers input")
		csContainerPopulator = qualysModule.qualys_log_populator.QualysCSContainerPopulator(settings=appConfig, checkpoint=cp, host=h, index=i, start_date=start_date, event_writer=ew)
		csContainerPopulator.run()

	if log_fim_events_api:
		cp = './fim_events'
		qlogger.info("Running FIM Events input")
		filename = "fim_events.json"
		fimEventsPopulator = qualysModule.qualys_log_populator.QualysFimEventsPopulator(settings=appConfig, checkpoint=cp, host=h, index=i, start_date=start_date, event_writer=ew)
		fimEventsPopulator.run()

	if log_fim_ignored_events_api:
		cp = './fim_ignored_events'
		qlogger.info("Running FIM Ignored Events input")
		filename = "fim_ignored_events.json"
		fimEventsPopulator = qualysModule.qualys_log_populator.QualysFimIgnoredEventsPopulator(settings=appConfig, checkpoint=cp, host=h, index=i, start_date=start_date, event_writer=ew)
		fimEventsPopulator.run()

	if log_fim_incidents_api:
		cp = './fim_incidents'
		qlogger.info("Running FIM Incidents input")
		filename = "fim_incidents.json"
		fimEventsPopulator = qualysModule.qualys_log_populator.QualysFimIncidentsPopulator(settings=appConfig, checkpoint=cp, host=h, index=i, start_date=start_date, event_writer=ew)
		fimEventsPopulator.run()

	if log_edr_api:
		cp = './edr_events'
		qlogger.info("Running EDR events information input")
		iocEventsPopulator = qualysModule.qualys_log_populator.QualysIOCEventsPopulator(settings=appConfig, checkpoint=cp, host=h, index=i, start_date=start_date,event_writer = ew)
		iocEventsPopulator.run()

	if log_activity_log_api:
		cp = './activity_log'
		qlogger.info("Running Activity Log input")
		activityLogPopulator = qualysModule.qualys_log_populator.QualysActivityLogPopulator(settings=appConfig, checkpoint=cp, host=h, index=i, start_date=start_date,event_writer = ew)
		activityLogPopulator.run()

	if log_sem_api:
		cp = './sem_detection'
		qlogger.info("Running SEM Detection input")
		semDetectionPopulator = qualysModule.qualys_log_populator.QualysSemDetectionPopulator(settings=appConfig, checkpoint=cp, host=h, index=i, start_date=start_date,event_writer = ew)
		semDetectionPopulator.run()

except qualysModule.splunkpopulator.utils.QualysAPIClientException as e:
	qlogger.error(str(e))