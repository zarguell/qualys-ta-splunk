# -*- coding: utf-8 -*-
import six.moves.urllib.parse as urlpars
import six
from io import open
from six.moves import range

__author__ = "Qualys, Inc"
__copyright__ = "Copyright (C) 2018, Qualys, Inc"
__license__ = "New BSD"
__version__ = "1.0"
from abc import ABCMeta

import sys, os, re
import json
import logging
import time
from datetime import datetime, timedelta

from defusedxml import ElementTree as ET

import splunk.clilib.cli_common as scc

import qualysModule
from qualysModule.splunkpopulator.basepopulator import BasePopulatorException
from qualysModule.splunkpopulator.kbpopulator import *
from qualysModule.splunkpopulator.detectionpopulator import *
from qualysModule.splunkpopulator.policypopulator import *
from qualysModule.splunkpopulator.cspopulator import *
from qualysModule.splunkpopulator.fimpopulator import *
from qualysModule.splunkpopulator.FIMEventsFetchCoordinator import FIMEventsFetchCoordinator
from qualysModule.splunkpopulator.FIMIncidentsFetchCoordinator import FIMIncidentsFetchCoordinator
from qualysModule.splunkpopulator.DetectionFetchCoordinator import DetectonFetchCoordinator
from qualysModule.splunkpopulator.WASFindingsFetchCoordinator import WASFindingsFetchCoordinator
from qualysModule.splunkpopulator.PostureInfoFetchCoordinator import PostureInfoFetchCoordinator
from qualysModule.splunkpopulator.CSImageFetchCoordinator import CsImageFetchCoordinator
from qualysModule.splunkpopulator.CSContainerFetchCoordinator import CsContainerFetchCoordinator
from qualysModule.splunkpopulator.iocpopulator import IocEventsPopulatorConfiguration, IOCEventsPopulator, IOCEventsCount
from qualysModule.splunkpopulator.activityLogPopulator import *
from qualysModule.splunkpopulator.semdetectionpopulator import *
from qualysModule.splunkpopulator.pcrspopulator import *
from qualysModule.splunkpopulator.PCRSPostureInfoFetchCoordinator import PCRSPostureInfoFetchCoordinator
from qualysModule import *
from qualysModule.lib import api as qapi
from qualysModule.splunkpopulator.utils import bool_value, convertTimeFormat, get_seed_file_path, is_cloud
import qualysModule.application_configuration


class QualysBaseLogPopulator(six.with_metaclass(ABCMeta, object)):
	formatter = logging.Formatter('%(message)s')
	console_log_handler = logging.StreamHandler(sys.stdout)
	console_log_handler.setFormatter(formatter)

	def __init__(self, settings=None, checkpoint=None, host='localhost', index='main',
				 start_date='1999-01-01T00:00:00Z', event_writer=None, server_info=None):

		"""

        :param settings qualysModule.application_configuration.ApplicationConfiguration:
        :param api_user:
        :param api_password:
        """
		if settings is None:
			self.settings = qualysModule.application_configuration.ApplicationConfiguration()
			self.settings.load()
			qlogger.debug("Loading default application settings")
		elif isinstance(settings, qualysModule.application_configuration.ApplicationConfiguration):
			self.settings = settings
			qlogger.debug("Loading custom settings")
		else:
			raise NameError("Invalid setting object specified")

		self.HOST = host
		self.INDEX = index
		self.STARTDATE = start_date
		self.EVENT_WRITER = event_writer
		self.checkpoint = checkpoint
		self.checkpointData = {}
		self.loadCheckpoint()
		self.server_info = server_info
		self.qualysConf = scc.getMergedConf("qualys")

	def loadCheckpoint(self):
		if os.path.isfile(self.checkpoint):
			# read file data and load into self.checkpointData
			try:
				with open(self.checkpoint) as f:
					self.checkpointData = json.load(f)
			except (OSError, IOError):
				sys.stderr.write("Failed to read Checkpoint from file %s" % self.checkpoint)
			return None
		else:
			# checkpoint file does not exists.
			# create a new one
			self.saveCheckpoint()

	# end of loadCheckpoint

	def saveCheckpoint(self):
		# dump contents of self.checkpointData into self.checkpoint
		try:
			json.dumps(self.checkpointData)
			with open(self.checkpoint, "w") as f:
				ckpt = json.dumps(self.checkpointData)
				if sys.version_info[0] < 3:
					f.write(ckpt.decode('utf-8'))
				else:
					f.write(ckpt)
		except (OSError, IOError):
			sys.stderr.write("Failed to write checkpoint in file %s" % self.checkpoint)

	# end of saveCheckpoint

	def get_app_setting(self, key):
		return self.settings.get(key)

	def save_app_setting(self, key, value):
		self.settings.set(key, value)

	def save_settings(self):
		self.settings.save_settings()

	def run(self):
		"""


        :type configuration_dict: dict
        :param api_user:
        :param api_password:
        :param configuration_dict:
        """

		qlogger.info("Start")

		self._run()
# end of QualysBaseLogPopulator class

class QualysKBPopulator(QualysBaseLogPopulator):

	def _run(self):
		"""
        :rtype : object
        :type configuration_dict: dict
        :param api_user:
        :param api_password:
        :param configuration_dict:
        """

		qlogger.info("Start logging knowledgebase")
		try:
			output_to_stdout = True
            
			# first read from config file then check if an option was provided on command line
			log_output_directory = self.settings.get('log_output_directory', None)

			if log_output_directory is not None and log_output_directory != '':
				output_to_stdout = False

			kb_logger = logging.getLogger('KNOWLEDGEBASE')

			start_time = datetime.utcnow()

			if output_to_stdout:
				qlogger.info("Outputting logs to stdout")
				kb_logger.addHandler(self.console_log_handler)
			else:
				kb_output_file = log_output_directory + '/qualys_knowledgebase.seed'
				kb_log_handler = logging.FileHandler(kb_output_file)
				kb_logger.addHandler(kb_log_handler)
				kb_log_handler.setFormatter(self.formatter)
				qlogger.info("Outputting knowledgebase data to file %s",
							 kb_output_file)

			knowledgebase_configuration = KnowledgebasePopulatorConfiguration(kb_logger)
			knowledgebase_configuration.index = self.INDEX
			knowledgebase_configuration.host = self.HOST

			# Whether to index knowledgebase data or not
			is_index_knowledgebase = bool_value(self.qualysConf['setupentity'].get('is_index_knowledgebase', '0'))
			qlogger.info("Index the knowledge base: %s", is_index_knowledgebase)

			is_create_lookup_csv = not is_index_knowledgebase
			qlogger.info("Create CSV lookup: %s", is_create_lookup_csv)

			lookup_destination = ""
			search_lookup_destination = ""
			TA_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
			if is_index_knowledgebase:
				lookup_destination = TA_ROOT + '/lookups/qualys_kb.csv'

				if os.path.isfile(lookup_destination):
					# Use date as 1999-01-01T00:00:00Z if checkpoint file is empty & KB CSV file exists
					cp_last_run_datetime = self.checkpointData.get('last_run_datetime', "1999-01-01T00:00:00Z")
				else:
					# Use date as Start Date provided on data input if checkpoint file is empty & KB CSV file doesn't exists
					cp_last_run_datetime = self.checkpointData.get('last_run_datetime', self.STARTDATE)

				last_fetched_date_time = ""
				if cp_last_run_datetime:
					try:
						qlogger.info("Fetching knowledgebase data since %s", cp_last_run_datetime)
						last_fetched_date_time = datetime.strptime(cp_last_run_datetime, '%Y-%m-%dT%H:%M:%SZ')
						knowledgebase_configuration.add_knowledgebase_api_filter('last_modified_after', cp_last_run_datetime)
						qlogger.info("Fetching knowledgebase data which were modified after %s", cp_last_run_datetime)
					except ValueError:
						qlogger.error("Incorrect date format found: %s. The correct date format is: yyyy-mm-ddTHH-MM-SSZ.", cp_last_run_datetime)
			else:
				SPLUNK_HOME_PATH = os.path.dirname(TA_ROOT)
				search_lookup_destination = SPLUNK_HOME_PATH + '/search/lookups/qualys_kb.csv'

			log_kb_additional_fields = bool_value(self.qualysConf['setupentity'].get('log_kb_additional_fields', '0'))
			qlogger.info("Log additional knowledgebase fields: %s", log_kb_additional_fields)

			kbPopulator = QualysKnowledgebasePopulator(knowledgebase_configuration, self.EVENT_WRITER)
			kbPopulator.create_lookup_csv = is_create_lookup_csv
			kbPopulator.index_knowledgebase = is_index_knowledgebase
			kbPopulator.log = True
			
			if log_kb_additional_fields:
				kbPopulator.CSV_HEADER_COLUMNS = kbPopulator.CSV_HEADER_COLUMNS + kbPopulator.QID_EXTRA_FIELDS_TO_LOG

			try:
				resp = kbPopulator.run()
				total_qid_logged = kbPopulator.get_qid_logged_count

                # Update checkpoint at this point
				if total_qid_logged > 0:
					self.checkpointData['last_run_datetime'] = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
					qlogger.info("Setting checkpointData last_run_datetime to %s" % self.checkpointData['last_run_datetime'])
					qlogger.info("Updating checkpoint to %s", self.checkpointData['last_run_datetime'])
					self.saveCheckpoint()

					# Remove the existing qualys_kb.csv file if indexing is enabled & CSV file exists 
					if is_index_knowledgebase and lookup_destination:
						if os.path.isfile(lookup_destination):
							qlogger.info("Removing qualys_kb.csv file from TA-QualysCloudPlatform/lookups folder")
							os.remove(lookup_destination)
						else:
							qlogger.info("qualys_kb.csv file not found in TA-QualysCloudPlatform/lookups folder")
				elif total_qid_logged == 0 and is_create_lookup_csv and search_lookup_destination:
					if os.path.isfile(search_lookup_destination):
						qlogger.info("Removing qualys_kb.csv file from search/lookups folder")
						os.remove(search_lookup_destination)
					else:
						qlogger.info("qualys_kb.csv file not found in search/lookups folder")
			except BasePopulatorException as e:
				if hasattr(e, 'message'):
					qlogger.error(e.message)
				else:
					qlogger.error(e)
			except NameError as e:
				if hasattr(e, 'message'):
					qlogger.error(e.message)
				else:   
					qlogger.error(e)

		except Exception as e:
			if hasattr(e, 'message'):
				qlogger.exception(e.message)
			else: 
				qlogger.exception(e)

		qlogger.info('Done logging knowledgebase')
# end of QualysKBPopulator class

class QualysDetectionPopulator(QualysBaseLogPopulator):
	def _run(self, configuration_dict=None):
		"""
        :rtype : object
        :type configuration_dict: dict
        :param api_user:
        :param api_password:
        :param configuration_dict:
        """

		try:
			output_to_stdout = True

			# first read from config file then check if an option was provided on command line
			log_output_directory = self.settings.get('log_output_directory', None)

			if log_output_directory is not None and log_output_directory != '':
				output_to_stdout = False

			detection_logger = logging.getLogger('HOST_DETECTIONS')

			start_time = datetime.utcnow()

			knowledgebase_configuration = KnowledgebasePopulatorConfiguration(detection_logger)
			knowledgebase_configuration.index = self.INDEX
			knowledgebase_configuration.host = self.HOST

			kbPopulator = QualysKnowledgebasePopulator(knowledgebase_configuration, self.EVENT_WRITER)

			log_detections = bool_value(self.qualysConf['setupentity'].get('log_detections', '1'))
			log_host_summary = bool_value(self.qualysConf['setupentity'].get('log_host_summary', '1'))

			full_pull_enabled = bool_value(self.qualysConf['setupentity'].get('enable_full_pull', '0'))
			seed_file_enabled = bool_value(self.qualysConf['setupentity'].get('enable_seed_file_generation', '0'))

			qlogger.info("Full data pull enabled? %s", full_pull_enabled)
			qlogger.info("Seed file option enabled? %s", seed_file_enabled)

			cp_last_run_datetime = None

			if log_detections or log_host_summary:

				if not qapi.client.qweb_version or qapi.client.qweb_version < (8,3):
					qlogger.info('Fetching KB as part of detections because qweb_version=%s is less than 8.3.',
								 qapi.client.qweb_version)
					kbPopulator.run()
				detection_configuration = HostDetectionPopulatorConfiguration(kbPopulator, detection_logger)
				if full_pull_enabled:
					cp_last_run_datetime = self.STARTDATE
				else:
					cp_last_run_datetime = self.checkpointData.get('last_run_datetime', self.STARTDATE)

				if seed_file_enabled in [1, '1', True, 'True']:
					seed_file_path = self.qualysConf['setupentity'].get('seed_file_path', '')
					if is_cloud(self.server_info):
						seed_file_path = get_seed_file_path(seed_file_path, True)

					path_to_check = None
					if os.path.isdir(seed_file_path):
						seed_file_name = seed_file_path + "/%s_TA_QualysCloudPlatform.seed" % datetime.now().strftime('%Y_%m_%d_%H_%M_%S')
						path_to_check = seed_file_path
					else:
						path_to_check = os.path.dirname(seed_file_path)
						seed_basename = os.path.basename(seed_file_path)
						seed_file_name = path_to_check + "/%s_%s" % (datetime.now().strftime('%Y_%m_%d_%H_%M_%S'), seed_basename)

					if path_to_check is not None:
						if not os.path.exists(path_to_check):
							qlogger.error("Path set for .seed file does not exist. Cannot proceed further. Path: %s", seed_file_path)
							exit(0)


					qlogger.info("TA will write events to seed file %s", seed_file_name)
					seed_fh = logging.FileHandler(seed_file_name)
					formatter = logging.Formatter("%(message)s")
					seed_fh.setFormatter(formatter)
					detection_logger.addHandler(seed_fh)
					qlogger.info("FileHandler added to detection loggger.")
				else:
					qlogger.info("TA will stream events directly into Splunk over stdout.")

				detection_configuration.add_detection_api_filter('status', 'New,Active,Fixed,Re-Opened')

				# List of host fields to be logged
				host_fields_to_log = self.qualysConf['setupentity'].get('host_fields_to_log', '')
				qlogger.info("Host fields to log: %s", host_fields_to_log)

				# List of detection fields to be logged
				detection_fields_to_log = self.qualysConf['setupentity'].get('detection_fields_to_log', '')
				qlogger.info("Detection fields to log: %s", detection_fields_to_log)

				# Max allowed characters in RESULTS field
				max_allowed_results_field_len = self.qualysConf['setupentity'].get('max_allowed_results_field_len', '0')
				qlogger.info("Max allowed characters in results field: %s", max_allowed_results_field_len)

				last_fetched_date_time = ''
				if cp_last_run_datetime:
					try:
						qlogger.info("Fetching VM detection data since %s", cp_last_run_datetime)
						#SPLNKAPP-420 | if cp_last_run_datetime has a date with format 'yyyy-mm-dd'
						#Below line will create an ValueError: time data 'yyyy-mm-dd' does not match format '%Y-%m-%dT%H:%M:%SZ'
						last_fetched_date_time = datetime.strptime(cp_last_run_datetime, '%Y-%m-%dT%H:%M:%SZ')
						detection_configuration.add_detection_api_filter('vm_processed_after', cp_last_run_datetime)
						qlogger.info("Fetching detection data for Hosts which were scanned after %s",
									 cp_last_run_datetime)
					except ValueError:
						qlogger.error("Incorrect date format found: %s. The correct date format is: yyyy-mm-ddTHH-MM-SSZ.", cp_last_run_datetime)

				qlogger.info("Fetching all detection data")

				# Truncation limit
				detection_truncation_limit = default_host_truncation_limit = self.qualysConf['setupentity'].get('detection_truncation_limit', '1000')

				# setup custom detection api parameters
				extra_params = None
				if 'detection_params' in self.qualysConf['setupentity'] and self.qualysConf['setupentity']['detection_params'] != '':
					qlogger.info("Parsing extra detection parameter string:%s",
								 self.qualysConf['setupentity']['detection_params'])
					try:
						extra_params = json.loads(self.qualysConf['setupentity']['detection_params'])
					except ValueError as e:
						qlogger.info("Parameters are not in JSON format, parsing as regular URL params: %s.",
									 self.qualysConf['setupentity']['detection_params'])
						extra_params = urlpars.parse_qs(self.qualysConf['setupentity']['detection_params'])
						extra_params = dict(map(lambda k_v: (k_v[0], ','.join(k_v[1])), iter(list(extra_params.items()))))

					if extra_params:
						for name in extra_params:
							qlogger.info("Adding detection param:%s with value: %s", name, extra_params[name])
							detection_configuration.add_detection_api_filter(name, extra_params[name], True) # True indicates its user-defined

							if name == "truncation_limit":
								detection_truncation_limit = extra_params[name]
					else:
						qlogger.error("Error setting extra detection API parameters via string: %s",
									  self.qualysConf['setupentity']['detection_params'])

				detection_configuration.host = self.HOST
				detection_configuration.index = self.INDEX
				detection_configuration.collect_advanced_host_summary = True
				detection_configuration.log_host_detections = log_detections
				detection_configuration.log_host_summary = log_host_summary
				detection_configuration.truncation_limit = detection_truncation_limit
				detection_configuration.default_host_truncation_limit = default_host_truncation_limit
				detection_configuration.log_host_details_in_detection = bool_value(self.qualysConf['setupentity']['log_host_details_in_detections'])
				detection_configuration.full_pull_enabled = full_pull_enabled
				detection_configuration.seed_file_enabled = seed_file_enabled
				detection_configuration.host_fields_to_log = host_fields_to_log
				detection_configuration.detection_fields_to_log = detection_fields_to_log
				detection_configuration.max_allowed_results_field_len = int(max_allowed_results_field_len)

				try:
					# configure which fields to log for HOSTSUMMARY events
					# if self.settings.get('host_summary_fields'):
					#	HostDetectionPopulator.host_fields_to_log = self.settings.get('host_summary_fields')

					# Setup which fields to log for HOSTVULN events
					# if self.settings.get('detection_fields'):
					#	HostDetectionPopulator.detection_fields_to_log = self.settings.get('detection_fields')

					use_multi_threading = bool_value(self.qualysConf['setupentity']['use_multi_threading'])

					total_logged = 0
					if use_multi_threading:
						num_threads = int(self.qualysConf['setupentity']['num_threads'])
						if num_threads < 0 or num_threads > 10:
							num_threads = 2
						config = {"num_threads": num_threads, "cp_last_run_datetime": cp_last_run_datetime}
						qlogger.info("Running in multi-thread mode with num_threads= %s", num_threads)
						dfc = DetectonFetchCoordinator(config, detection_configuration, self.EVENT_WRITER)
						dfc.coordinate()
						total_logged = dfc.get_host_logged_count
					else:
						qlogger.info("Running in single thread mode")
						detection_api_populator = HostDetectionPopulator(detection_configuration, self.EVENT_WRITER)
						detection_api_populator.run()
						total_logged = detection_api_populator.get_host_logged_count

					qlogger.info("Done loading detections for %d hosts.", total_logged)

					# store date/time when data pull was started, only if atlease one host was logged
					# TODO: update checkpoint at this point
					if total_logged > 0:
						if not full_pull_enabled:
							self.checkpointData['last_run_datetime'] = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
							qlogger.info("Setting checkpointData last_run_datetime to %s" % self.checkpointData['last_run_datetime'])

							first_run = self.checkpointData.get('first_run', True)
							if first_run:
								self.checkpointData['first_run'] = False

							qlogger.info("Updating checkpoint to %s", self.checkpointData['last_run_datetime'])
							self.saveCheckpoint()
						else:
							qlogger.info("Full pull is enabled. No need to update the checkpoint.")
						# if full pull is not enabled

				except BasePopulatorException as e:
					if hasattr(e, 'message'):
						qlogger.error(e.message)
					else:
						qlogger.error(e)

		except Exception as e:
			qlogger.exception("An error occurred while running Host Detection Populator.")
		qlogger.info("Qualys Host Detection Populator finished.")
# end of QualysDetectionPopulator class

class QualysWasDetectionPopulator(QualysBaseLogPopulator):
	def _run(self, configuration_dict=None):
		"""
        :rtype : object
        :type configuration_dict: dict
        :param api_user:
        :param api_password:
        :param configuration_dict:
        """

		try:
			detection_logger = logging.getLogger('WAS_DETECTIONS')

			start_time = datetime.utcnow()

			knowledgebase_configuration = KnowledgebasePopulatorConfiguration(detection_logger)
			knowledgebase_configuration.index = self.INDEX
			knowledgebase_configuration.host = self.HOST

			kbPopulator = QualysKnowledgebasePopulator(knowledgebase_configuration, self.EVENT_WRITER)

			log_detections = bool_value(self.qualysConf['setupentity']['log_individual_findings'])
			log_host_summary = bool_value(self.qualysConf['setupentity']['log_webapp_summary'])

			if log_detections or log_host_summary:
				detection_configuration = WASDetectionPopulatorConfiguration(kbPopulator, detection_logger)
				cp_last_run_datetime = self.checkpointData.get('last_run_datetime', self.STARTDATE)

				last_fetched_date_time = ''
				if cp_last_run_datetime:
					try:
						qlogger.info("WAS findings were last fetched on %s", cp_last_run_datetime)
						last_fetched_date_time = datetime.strptime(cp_last_run_datetime, '%Y-%m-%dT%H:%M:%SZ')

						detection_configuration.add_detection_api_filter('lastTestedDate', 'GREATER',
																		 cp_last_run_datetime)
						qlogger.info("Fetching WAS findings data for Hosts which were scanned after %s",
									 cp_last_run_datetime)
					except ValueError:
						qlogger.error("Incorrect date format found: %s", last_fetched_date_time)

				qlogger.info("Fetching all WAS detection data")

				# setup custom detection api parameters

				extra_params = None
				if 'extra_was_params' in self.qualysConf['setupentity'] and self.qualysConf['setupentity'][
					'extra_was_params'] != '':
					qlogger.info("Parsing extra WAS parameter string:%s", self.qualysConf['setupentity']['extra_was_params'])
					try:
						extra_params_root = ET.fromstring(self.qualysConf['setupentity']['extra_was_params'])

						for child in extra_params_root:
							child_attribs = child.attrib
							qlogger.info("Adding WAS param: %s %s %s", child_attribs['field'],
										 child_attribs['operator'], child.text)
							detection_configuration.add_detection_api_filter(child_attribs['field'],
																			 child_attribs['operator'], child.text)
					except ValueError as e:
						qlogger.info("Error parsing extra WAS parameters: %s Error: %s",
									 self.qualysConf['setupentity']['extra_was_params'], e.message)

				detection_configuration.host = self.HOST
				detection_configuration.index = self.INDEX
				detection_configuration.collect_advanced_host_summary = True
				detection_configuration.log_host_detections = log_detections
				detection_configuration.log_host_summary = log_host_summary
				detection_configuration.truncation_limit = 5000
				detection_configuration.log_host_details_in_detection = bool_value(
					self.qualysConf['setupentity']['log_host_details_in_detections'])

				try:
					# configure which fields to log for HOSTSUMMARY events

					if self.settings.get('host_summary_fields'):
						WASDetectionPopulator.host_fields_to_log = self.settings.get('host_summary_fields')

					# Setup which fields to log for HOSTVULN events
					if self.settings.get('detection_fields'):
						WASDetectionPopulator.detection_fields_to_log = self.settings.get('detection_fields')

					use_multi_threading = False
					if 'use_multi_threading_for_was' in self.qualysConf['setupentity']:
						use_multi_threading = bool_value(self.qualysConf['setupentity']['use_multi_threading_for_was'])

					total_logged = 0

					if use_multi_threading:
						num_threads = int(self.qualysConf['setupentity']['num_threads_for_was'])
						if num_threads < 0 or num_threads > 10:
							num_threads = 2
						config = {"num_threads": num_threads}
						qlogger.info("Running in multi-thread mode with num_threads=%s", num_threads)
						wfc = WASFindingsFetchCoordinator(num_threads, detection_configuration, self.EVENT_WRITER)
						wfc.coordinate()
						total_logged = wfc.getLoggedHostsCount()
					else:
						qlogger.info("Running in single thread mode")
						detection_api_populator = WASDetectionPopulator(detection_configuration, self.EVENT_WRITER)
						detection_api_populator.run()
						total_logged = detection_api_populator.get_host_logged_count

					qlogger.info("Done loading %d WAS findings.", total_logged)

					# store date/time when data pull was started, only if atlease one host was logged
					if total_logged > 0:
						self.checkpointData['last_run_datetime'] = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
						qlogger.info("setting checkpointData last_run_datetime to %s" % self.checkpointData['last_run_datetime'])

						first_run = self.checkpointData.get('first_run', True)
						if first_run:
							self.checkpointData['first_run'] = False

						self.saveCheckpoint()

				except BasePopulatorException as e:
					if hasattr(e, 'message'):
						qlogger.error(e.message)
					else:
						qlogger.error(e)

		except Exception as e:
			qlogger.exception("An error occurred while running WAS Detection Populator.")
		qlogger.info("Qualys WAS Detection Populator finished.")
# end of QualysWasDetectionPopulator class

class QualysPCPosturePopulator(QualysBaseLogPopulator):
	def _run(self):
		"""
		:rtype : object
		:type configuration_dict: dict
		:param api_user:
		:param api_password:
		:param configuration_dict:
		"""
		qlogger.info("Qualys PC Posture Populator started.")
		try:

			posture_logger = logging.getLogger('POLICY_POSTURE_INFO')

			cp_last_run_datetime = None
			log_individual_events = bool_value(self.qualysConf['setupentity'].get('log_individual_compliance_events', '0'))
			log_summary_events = bool_value(self.qualysConf['setupentity'].get('log_policy_summary', '0'))
			qlogger.info("Log individual PC posture info events? %s", log_individual_events)
			qlogger.info("Log PC posture info summary events? %s", log_summary_events)

			posture_configuration = PosturePopulatorConfiguration(posture_logger)
			posture_configuration.host = self.HOST
			posture_configuration.index = self.INDEX
			posture_configuration.log_individual_events = log_individual_events
			posture_configuration.log_summary_events = log_summary_events
			if self.qualysConf['setupentity']['pc_details'] not in ["1","0","True","False"]:
				qlogger.warning("'Details' should be 1/True(All) or 0/False(Basic). Value given in /qualys.conf - %s. Using default value '0(Basic)'.", self.qualysConf['setupentity']['pc_details'])
				posture_configuration.details = False
			else:
				posture_configuration.details = bool_value(self.qualysConf['setupentity'].get('pc_details', '0'))

			if self.qualysConf['setupentity']['pc_extra_details'] not in ["1","0","True","False"]:
				qlogger.warning("'Additional fields' should be 1/True(Yes) or 0/False(No). Value given in /qualys.conf - %s. Using default value '0(No)'.", self.qualysConf['setupentity']['pc_extra_details'])
				posture_configuration.extra_details = False
			else:
				posture_configuration.extra_details =  bool_value(self.qualysConf['setupentity'].get('pc_extra_details', '0'))

			if log_individual_events or log_summary_events:
				# first, populate policy csv lookup file, and also stream that data into Splunk
				cp_last_run_datetime = self.checkpointData.get('last_run_datetime', self.STARTDATE)
				qlogger.info("Pulling information about policies updated after %s", cp_last_run_datetime)

				# setting date-time from where to pull the data
				if cp_last_run_datetime is not None:
					posture_configuration.add_posture_api_filter('status_changes_since', cp_last_run_datetime)

				# setting user-defined extra api parameters
				if 'extra_posture_params' in self.qualysConf['setupentity'] and self.qualysConf['setupentity']['extra_posture_params'] != '':
					qlogger.info("Extra posture info api param(s) set by user are: %s", self.qualysConf['setupentity']['extra_posture_params'])
					extra_params = None

					try:
						extra_params = json.loads(self.qualysConf['setupentity']['extra_posture_params'])
					except ValueError as e:
						qlogger.info("Extra posture params are not in JSON format. Parsing them as query string.")
						extra_params = urlpars.parse_qs(self.qualysConf['setupentity']['extra_posture_params'])
						extra_params = dict(map(lambda k_v1: (k_v1[0], ','.join(k_v1[1])), iter(list(extra_params.items()))))

					if extra_params:
						for name in extra_params:
							posture_configuration.add_posture_api_filter(name, extra_params[name], True) # True indicates its user-defined
							posture_configuration.cause_of_failure = posture_configuration.get_posture_api_param_value('cause_of_failure')
							posture_configuration.remediation = posture_configuration.get_posture_api_param_value('show_remediation_info')

				policy_stream_handler = logging.StreamHandler(stream=sys.stdout)
				policy_formatter = logging.Formatter("%(message)s")
				policy_stream_handler.setFormatter(policy_formatter)
				posture_logger.addHandler(policy_stream_handler)
				qlogger.info("StreamHandler added to posture_logger.")

				# second, pull policy posture information
				r = range(1, 11)
				pc_multi_threading_enabled = bool_value(self.qualysConf['setupentity']['pc_multi_threading_enabled'])
				num_threads = 1 # default value. This input will always run with thread(s).
				if pc_multi_threading_enabled:
					if int(self.qualysConf['setupentity']['num_threads_for_pc']) in r:
						num_threads = int(self.qualysConf['setupentity']['num_threads_for_pc'])
						qlogger.info("PC Posture Information input running in multi-thread mode with %s threads.", num_threads)
					else:
						qlogger.warning("Number of threads are out of range. Given thread value - %s."
										"Now, PC Posture Information running in multi-thread mode with 2 threads.",
										int(self.qualysConf['setupentity']['num_threads_for_pc']))
						num_threads = 2
				else:
					qlogger.info("PC Posture Information input running in single thread mode.")

				# Assign single policy id to PC Posture Information API - SPLNKAPP-1139
				pc_num_count_for_pid = int(self.qualysConf['setupentity'].get('pc_num_count_for_pid', '1'))
				if pc_num_count_for_pid != 1:
					qlogger.warning("Invalid value %s set for number of POLICY IDs. Using default value 1.", pc_num_count_for_pid)
					pc_num_count_for_pid = 1
				qlogger.info("Number of Policy IDs to set in each PC Posture Information API call: %d", pc_num_count_for_pid)

				# Number of posture info records per API request - SPLNKAPP-1140
				pc_truncation_limit = int(self.qualysConf['setupentity'].get('pc_truncation_limit', '1000'))
				posture_configuration.pc_truncation_limit = pc_truncation_limit
				qlogger.info("Number of posture info records per API request: %d", pc_truncation_limit)

				pifc = PostureInfoFetchCoordinator(num_threads, pc_num_count_for_pid, self.EVENT_WRITER, posture_configuration)
				pifc.coordinate()
				total_logged = pifc.get_logged_controls_count
				qlogger.info("PC Posture Information input logged %d entries.", total_logged)

				if total_logged > 0:
					self.checkpointData['last_run_datetime'] = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
					qlogger.info("Updating Policy Compliance Posture Information checkpoint to %s", self.checkpointData['last_run_datetime'])
					first_run = self.checkpointData.get('first_run', True)

					if first_run:
						self.checkpointData['first_run'] = False

					self.saveCheckpoint()

		except Exception as e:
			qlogger.exception("An error occurred while running PC Posture Populator.")
		qlogger.info("Qualys PC Posture Populator finished.")
	# end of _run()
# end of QualysPCPosturePopulator class

class QualysCSImagePopulator(QualysBaseLogPopulator):
	EXTRA_PARAMS = None

	def _run(self):
		"""
		:rtype : object
		:type configuration_dict: dict
		:param api_user:
		:param api_password:
		:param configuration_dict:
		"""
		start=datetime.now()
		qlogger.info("Qualys CS Image Populator started.")
		try:

			cs_logger = logging.getLogger('CS_DOCKER_IMAGE_INFO')

			cp_last_run_datetime = None
			cs_log_individual_events = bool_value(self.qualysConf['setupentity'].get('cs_log_individual_events', '0'))
			cs_log_summary_events = bool_value(self.qualysConf['setupentity'].get('cs_log_summary_events', '0'))
			cs_image_page_size = int(self.qualysConf['setupentity'].get('cs_image_page_size', '1000'))
			qlogger.info("Log individual CS info events? %s", cs_log_individual_events)
			qlogger.info("Log CS info summary events? %s", cs_log_summary_events)

			cs_configuration = CsImagePopulatorConfiguration(cs_logger)
			cs_configuration.host = self.HOST
			cs_configuration.index = self.INDEX
			cs_configuration.cs_log_individual_events = cs_log_individual_events
			cs_configuration.cs_log_summary_events = cs_log_summary_events
			cs_configuration.cs_image_page_size = cs_image_page_size
			cs_configuration.checkpointData = self.checkpointData

			if cs_log_individual_events or cs_log_summary_events:
				# first, populate cs lookup file, and also stream that data into Splunk
				cp_last_run_datetime = self.checkpointData.get('last_run_datetime', self.STARTDATE)
				qlogger.info("Pulling information about cs image updated after %s", cp_last_run_datetime)

				# setting date-time from where to pull the data
				if cp_last_run_datetime is not None:
					# Convert the cp_last_run_datetime into epoch time
					cs_configuration.start_date = cp_last_run_datetime
					end_date = datetime.utcnow() - timedelta(seconds=30)
					cs_configuration.end_date = end_date.strftime('%Y-%m-%dT%H:%M:%SZ')

				# setting user-defined extra api parameters
				if 'cs_extra_params' in self.qualysConf['setupentity'] and self.qualysConf['setupentity']['cs_extra_params'] != '':
					qlogger.info("Extra cs image info api param(s) set by user are: %s", self.qualysConf['setupentity']['cs_extra_params'])
					self.EXTRA_PARAMS = self.qualysConf['setupentity']['cs_extra_params']

					#Check extra params for lastScanned
					if "lastScanned" in self.EXTRA_PARAMS:
						qlogger.warning("lastScanned not allowed in Container Security extra API parameters."
										"Continuing the API call without extra parameters.")
					else:
						cs_configuration.add_cs_api_filter(self.EXTRA_PARAMS, True)  # True indicates its user-defined

				cs_stream_handler = logging.StreamHandler(stream=sys.stdout)
				cs_image_formatter = logging.Formatter("%(message)s")
				cs_stream_handler.setFormatter(cs_image_formatter)
				cs_logger.addHandler(cs_stream_handler)
				qlogger.info("StreamHandler added to cs_logger.")

				# second, pull policy posture information
				cs_multi_threading_enabled = bool_value(self.qualysConf['setupentity']['cs_multi_threading_enabled'])
				cs_num_threads = 1  # default value. This input will always run with thread(s).
				if cs_multi_threading_enabled:
					cs_num_threads = int(self.qualysConf['setupentity']['cs_num_threads'])
					if cs_num_threads < 0 or cs_num_threads > 10:
						cs_num_threads = 2
					qlogger.info("CS Images Information input running in multi-thread mode with %s threads.", cs_num_threads)
				else:
					qlogger.info("CS Images Information input running in single thread mode.")

				csiifc = CsImageFetchCoordinator(cs_num_threads, self.EVENT_WRITER, cs_configuration)
				csiifc.coordinate()
				total_logged_vuln = csiifc.get_logged_vulns_count
				total_logged_img = csiifc.get_logged_image_count
				qlogger.info("CS logged total Vulns=%d for Images=%d", total_logged_vuln,total_logged_img)

				if total_logged_img > 0 or total_logged_vuln > 0:
					#self.checkpointData['last_run_datetime'] = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
					qlogger.info("Updating CS Image Vuln Information checkpoint to %s",
								 self.checkpointData['last_run_datetime'])
					first_run = self.checkpointData.get('first_run', True)

					if first_run:
						self.checkpointData['first_run'] = False

					self.saveCheckpoint()
			qlogger.info("Total time taken to pull the data is %s.", datetime.now()-start)
		except Exception as e:
			qlogger.exception("An error occurred while running CS Image Populator.")
		qlogger.info("Qualys CS Image Populator finished.")
	# end of _run()
# end of QualysCSImagePopulator class

class QualysCSContainerPopulator(QualysBaseLogPopulator):
	def _run(self):
		qlogger.info("Qualys CS Container Populator started.")
		run_start=datetime.now()
		
		try:
			cs_logger = logging.getLogger('CS_LOGGER')
			
			cs_container_api_page_size = int(self.qualysConf['setupentity'].get('cs_container_api_page_size', '1000')) # default value: 1000
			cs_log_individual_container_events = bool_value(self.qualysConf['setupentity'].get('cs_log_individual_container_events', '0'))
			cs_log_container_summary_events = bool_value(self.qualysConf['setupentity'].get('cs_log_container_summary_events', '0'))
			qlogger.info("Log individual container info events? %s", cs_log_individual_container_events)
			qlogger.info("Log container summary events? %s", cs_log_container_summary_events)
			qlogger.info("Container API page size = %d", cs_container_api_page_size)
			
			if cs_log_individual_container_events or cs_log_container_summary_events:
				cs_configuration = CSContainerPopulatorConfiguration(cs_logger)
				cs_configuration.host = self.HOST
				cs_configuration.index = self.INDEX
				cs_configuration.cs_log_individual_events = cs_log_individual_container_events
				cs_configuration.cs_log_summary_events = cs_log_container_summary_events
				cs_configuration.page_size = cs_container_api_page_size
				cs_configuration.checkpointData = self.checkpointData
				
				last_run_datetime_checkpoint = self.checkpointData.get('last_run_datetime', self.STARTDATE)
				qlogger.info("Pulling information about containers updated since %s", last_run_datetime_checkpoint)
				if last_run_datetime_checkpoint is not None:
					# Convert the last_run_datetime_checkpoint into epoch time
					cs_configuration.start_date = last_run_datetime_checkpoint
					end_date = datetime.utcnow() - timedelta(seconds=30)
					cs_configuration.end_date = end_date.strftime('%Y-%m-%dT%H:%M:%SZ')
				
				if 'cs_container_extra_params' in self.qualysConf['setupentity'] and self.qualysConf['setupentity']['cs_container_extra_params'] != '':
					extra_filters = self.qualysConf['setupentity']['cs_container_extra_params']
					qlogger.info("Extra filter(s) set by user are: %s", extra_filters)
					valid, not_allowed_param = cs_configuration.validate_extra_filters(extra_filters)
					if valid:
						cs_configuration.extra_filters = extra_filters
					else:
						raise ValueError("Parameter '%s' is not allowed in Container Populator" % not_allowed_param)
				
				cs_stream_handler = logging.StreamHandler(stream=sys.stdout)
				cs_image_formatter = logging.Formatter("%(message)s")
				cs_stream_handler.setFormatter(cs_image_formatter)
				cs_logger.addHandler(cs_stream_handler)
				qlogger.info("StreamHandler added to cs_logger.")
				
				cs_multi_threading_enabled = bool_value(self.qualysConf['setupentity']['cs_container_multi_threading_enabled'])
				qlogger.info("Multi-threading enabled for CS Container feed? %s", cs_multi_threading_enabled)
				cs_num_threads = 1  # default value. This input will always run with thread(s).
				if cs_multi_threading_enabled:
					cs_num_threads = int(self.qualysConf['setupentity'].get('cs_container_num_threads', '1'))
					if cs_num_threads < 0 or cs_num_threads > 10:
						cs_num_threads = 2
					qlogger.info("Container Populator will run in multi-thread mode with %s threads.", cs_num_threads)
				else:
					qlogger.info("Container Populator will run in single thread mode.")
				
				cs_configuration.num_threads = cs_num_threads
				
				coordinator = CsContainerFetchCoordinator(self.EVENT_WRITER, cs_configuration)
				coordinator.coordinate()
				total_logged_containers = coordinator.get_logged_containers_count
				total_logged_vulns = coordinator.get_logged_vulns_count
				total_unique_containers = coordinator.get_unique_containers_count
				total_null_containers = coordinator.get_null_containers_count
				qlogger.info("Container Populator detected %d containers with container Id: null", total_null_containers)
				qlogger.info("Container Populator logged %d containers (total unique Containers: %d).", total_logged_containers, total_unique_containers)
				qlogger.info("Container Populator logged %d vulnerabilities.", total_logged_vulns)

				if total_logged_containers > 0:
					#self.checkpointData['last_run_datetime'] = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
					qlogger.info("Updating Container Vuln Information checkpoint to %s",
								 self.checkpointData['last_run_datetime'])
					first_run = self.checkpointData.get('first_run', True)

					if first_run:
						self.checkpointData['first_run'] = False

					self.saveCheckpoint()
			else:
				qlogger.warning("CS container feed: Neither individual events, nor summary events enabled. Nothing to log.")

			qlogger.info("Total time taken to pull the data is %s.", datetime.now()-run_start)
		except Exception as e:
			qlogger.exception("An error occurred while running CS Container Populator.")
		qlogger.info("Qualys CS Container Populator finished.")
	# end of _run
# end of QualysCSContainerPopulator

class QualysIOCEventsPopulator(QualysBaseLogPopulator):
	def _run(self):
		start=datetime.now()
		qlogger.info("Qualys EDR Events Populator started.")
		try:

			edr_logger = logging.getLogger('EDR_EVENTS_INFO')

			cp_last_run_datetime = None

			#Do the events configuration
			ioc_configuration = IocEventsPopulatorConfiguration(edr_logger)
			ioc_configuration.host = self.HOST
			ioc_configuration.index = self.INDEX
			ioc_configuration.pageSize = self.qualysConf['setupentity'].get('ioc_events_pageSize', '1000')

			# populate ioc events json file, and also stream that data into Splunk
			cp_last_run_datetime = self.checkpointData.get('last_run_datetime', self.STARTDATE)
			qlogger.info("Pulling information about EDR events updated after %s", cp_last_run_datetime)
			if cp_last_run_datetime is not None:
				ioc_configuration.fromDate = cp_last_run_datetime

			# setting user-defined extra api parameters
			if 'ioc_extra_params' in self.qualysConf['setupentity'] and self.qualysConf['setupentity']['ioc_extra_params'] != '':
				if "'dateTime':" in str(self.qualysConf['setupentity']['ioc_extra_params']):
					ValueError("dateTime parameter cannot be set in Extra Parameter. Please, provide the proper parameters.")
				else:
					ioc_configuration.add_ioc_api_filter(self.qualysConf['setupentity']['ioc_extra_params'],True)  # True indicates its user-defined

			ioc_stream_handler = logging.StreamHandler(stream=sys.stdout)
			ioc_events_formatter = logging.Formatter("%(message)s")
			ioc_stream_handler.setFormatter(ioc_events_formatter)
			edr_logger.addHandler(ioc_stream_handler)
			qlogger.info("StreamHandler added to edr_logger.")

			"""NOTE: in the /ioc/events and /ioc/events/count API call the toDate should be same. So allocating the current toDate from populator."""
			ioc_configuration.toDate = str(datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'))

			#Get the events count for the time period
			qlogger.debug("Getting the count of events in EDR.")
			iocCount = IOCEventsCount(ioc_configuration)
			iocCount.run()
			ioc_configuration.events_count = int(iocCount.get_events_count)

			#Index the events data for the time period
			qlogger.debug("Indexing the EDR events in Splunk.")
			ioc_configuration.checkpointData = self.checkpointData
			ioc_configuration.checkpoint = self.checkpoint

			qlogger.info("EDR Events Populator will run in non-thread mode.")
			iocifc = IOCEventsPopulator(self.EVENT_WRITER, ioc_configuration)
			iocifc.run()
			total_logged = iocifc.get_logged_events_count
			qlogger.info("EDR Events Information input logged total %d entries.", total_logged)

			if total_logged > 0:
				# self.checkpointData['last_run_datetime'] = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
				self.checkpointData['last_run_datetime'] = iocifc.last_record_dateTime
				qlogger.info("Updating EDR Events Information checkpoint to %s",
							 self.checkpointData['last_run_datetime'])
				first_run = self.checkpointData.get('first_run', True)

				if first_run:
					self.checkpointData['first_run'] = False

				self.saveCheckpoint()
			qlogger.info("Total time taken to pull the data is %s.", datetime.now()-start)
		except Exception as e:
			qlogger.exception("An error occurred while running EDR Events Populator.")
		qlogger.info("Qualys EDR Events Populator finished.")
	# end of _run()
# end of QualysIOCEventsPopulator class

class QualysFimEventsPopulator(QualysBaseLogPopulator):
	EXTRA_PARAMS = None

	def _run(self):
		start = datetime.now()
		qlogger.info("Qualys FIM Events Populator started.")
		try:
			qualysConf = scc.getMergedConf("qualys")

			fim_logger = logging.getLogger('FIM_EVENTS')

			cp_last_run_datetime = None
			fim_events_page_size = int(qualysConf['setupentity'].get('fim_events_page_size', '1000'))

			fim_configuration = FIMEventsPopulatorConfiguration(fim_logger)
			fim_configuration.events_api_path = "/fim/v2/events/search"
			fim_configuration.count_api_path = "/fim/v2/events/count"
			fim_configuration.index = self.INDEX
			fim_configuration.fim_events_page_size = fim_events_page_size
			fim_configuration.source_type = "qualys:fim:event"
			fim_configuration.event_type = "FIM_EVENT"
			fim_configuration.object_type = "FIM Event"
			fim_configuration.file_prifix = "fim_events_list"
			fim_configuration.checkpoint = self.checkpoint
			fim_configuration.checkpointData = self.checkpointData
			#subtract 30 seconds from current time to match the lag of elastic search indexing
			start_time = datetime.utcnow() - timedelta(seconds=30)

			cp_last_run_datetime = self.checkpointData.get('last_run_datetime', self.STARTDATE)
			try:
				datetime.strptime(cp_last_run_datetime, '%Y-%m-%dT%H:%M:%S.%fZ')
			except ValueError:		
				cp_last_run_datetime = cp_last_run_datetime[:-1]+".000Z"
				qlogger.info("Checkpoint/Start Date is converted to include milliseconds. Updated value is %s", cp_last_run_datetime)

			qlogger.info("Pulling information about FIM events updated after %s", cp_last_run_datetime)
			searchAfter = self.checkpointData.get('searchAfter', [])

			# setting date-time from where to pull the data
			if cp_last_run_datetime is not None:
				fim_configuration.dateTime_start = cp_last_run_datetime
				fim_configuration.dateTime_end = start_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+"Z"

			# setting user-defined extra api parameters
			if 'fim_events_extra_params' in qualysConf['setupentity'] and qualysConf['setupentity']['fim_events_extra_params'] != '':
				qlogger.info("Extra FIM events api param(s) set by user are: %s", qualysConf['setupentity']['fim_events_extra_params'])
				self.EXTRA_PARAMS = qualysConf['setupentity']['fim_events_extra_params']

				#Check extra params for dateTime
				if "dateTime" in self.EXTRA_PARAMS:
					qlogger.warning("dateTime not allowed in FIM events extra API parameters."
									"Continuing the API call without extra parameters.")
				else:
					fim_configuration.add_api_filter(self.EXTRA_PARAMS, True)  # True indicates its user-defined

			fim_stream_handler = logging.StreamHandler(stream=sys.stdout)
			fim_events_formatter = logging.Formatter("%(message)s")
			fim_stream_handler.setFormatter(fim_events_formatter)
			fim_logger.addHandler(fim_stream_handler)
			qlogger.info("StreamHandler added to fim_logger.")

			fim_multi_threading_enabled = qualysConf.get('setupentity').get('fim_events_multi_threading_enabled')
			if fim_multi_threading_enabled and bool_value(fim_multi_threading_enabled):
				if int(qualysConf['setupentity']['fim_events_num_threads']) > 1:
					qlogger.warning("TA Version 1.6.0 and above do not support multi-threading for FIM.  Old configuration of FIM for threading(if any) is ignored.")

			qlogger.info("FIM Populator will run in non-thread mode.")
			#PULL FIM EVENTS
			#get the count of fim events by calling count API
			fetcher = QualysFIMEventsCountFetcher(fim_configuration)
			fetcher.run()
			total_events_count = fetcher.getCount()
			qlogger.info("Approx count of FIM events to be logged: %s", total_events_count)
			
			total_logged_events = 0
			if total_events_count > 0:
				fimiifcEv = FIMEventsFetchCoordinator(total_events_count, self.EVENT_WRITER, fim_configuration, searchAfter)
				fimiifcEv.coordinate()
				
				total_logged_events = fimiifcEv.loggedEventsCount
				qlogger.info("FIM logged total Events=%d", total_logged_events)
			
			if total_logged_events > 0:
				#self.checkpointData['last_run_datetime'] = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
				qlogger.info("Updating FIM Events checkpoint to %s",
							 self.checkpointData['last_run_datetime'])
				first_run = self.checkpointData.get('first_run', True)

				if first_run:
					self.checkpointData['first_run'] = False

				self.saveCheckpoint()
				qlogger.info("Total time taken to pull the data is %s.", datetime.now()-start)
		except Exception as e:
			qlogger.exception("An error occured while running FIM Events Populator.")
		qlogger.info("Qualys FIM Events Populator finished.")
	# end of _run()
# end of QualysFimEventsPopulator class

class QualysFimIncidentsPopulator(QualysBaseLogPopulator):
	EXTRA_PARAMS = None

	def _run(self):
		start = datetime.now()
		qlogger.info("Qualys FIM Incidents Populator started.")
		try:
			qualysConf = scc.getMergedConf("qualys")

			fim_logger = logging.getLogger('FIM_INCIDENTS')

			cp_last_run_datetime = None
			fim_incidents_page_size = int(qualysConf['setupentity'].get('fim_incidents_page_size', '1000'))
			
			fim_configuration = FIMEventsPopulatorConfiguration(fim_logger)
			fim_configuration.index = self.INDEX
			fim_configuration.fim_events_page_size = fim_incidents_page_size
			fim_configuration.checkpoint = self.checkpoint
			fim_configuration.checkpointData = self.checkpointData
			
			start_time = datetime.utcnow()
			
			cp_last_run_datetime = self.checkpointData.get('last_run_datetime', self.STARTDATE)
			try:
				datetime.strptime(cp_last_run_datetime, '%Y-%m-%dT%H:%M:%S.%fZ')
			except ValueError:		
				cp_last_run_datetime = cp_last_run_datetime[:-1]+".000Z"
				qlogger.info("Checkpoint/Start Date is converted to include milliseconds. Updated value is %s", cp_last_run_datetime)
            
			qlogger.info("Pulling information about FIM incidents updated after %s", cp_last_run_datetime)

			# setting date-time from where to pull the data
			if cp_last_run_datetime is not None:
				fim_configuration.dateTime_start = cp_last_run_datetime
				fim_configuration.dateTime_end = start_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+"Z"

			# setting user-defined extra api parameters
			if 'fim_incidents_extra_params' in qualysConf['setupentity'] and qualysConf['setupentity']['fim_incidents_extra_params'] != '':
				qlogger.info("Extra FIM incidents api param(s) set by user are: %s", qualysConf['setupentity']['fim_incidents_extra_params'])
				self.EXTRA_PARAMS = qualysConf['setupentity']['fim_incidents_extra_params']

				#Check extra params for dateTime
				if "createdBy.date" in self.EXTRA_PARAMS:
					qlogger.warning("dateTime not allowed in FIM incidents extra API parameters."
									"Continuing the API call without extra parameters.")
				else:
					fim_configuration.add_api_filter(self.EXTRA_PARAMS, True)  # True indicates its user-defined

			fim_stream_handler = logging.StreamHandler(stream=sys.stdout)
			fim_events_formatter = logging.Formatter("%(message)s")
			fim_stream_handler.setFormatter(fim_events_formatter)
			fim_logger.addHandler(fim_stream_handler)
			qlogger.info("StreamHandler added to fim_logger.")

			fim_incidents_multi_threading_enabled = qualysConf.get('setupentity').get('fim_incidents_multi_threading_enabled')
			if fim_incidents_multi_threading_enabled and bool_value(fim_incidents_multi_threading_enabled):
				if int(qualysConf['setupentity']['fim_incidents_num_threads']) > 1:
					qlogger.warning("TA Version 1.6.0 and above do not support multi-threading for FIM.  Old configuration FIM for threading(if any) is ignored.")

			qlogger.info("FIM Populator will run in non-thread mode.")

			#PULL FIM Incidents
			#get the count of fim incidents by calling count API
			fetcher = QualysFIMIncidentsCountFetcher(fim_configuration)
			fetcher.run()
			total_incidents_count = fetcher.getCount()
			
			total_logged_incidents = 0
			if total_incidents_count > 0:
				fimiifcIn = FIMIncidentsFetchCoordinator(total_incidents_count, self.EVENT_WRITER, fim_configuration)
				fimiifcIn.coordinate()
				
				total_logged_incidents = fimiifcIn.loggedIncidentsCount
				qlogger.info("FIM logged total Incidents=%d", total_logged_incidents)

			if total_logged_incidents > 0:
				self.checkpointData['last_run_datetime'] = start_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+"Z"
				qlogger.info("Updating FIM Incidents checkpoint to %s",
							 self.checkpointData['last_run_datetime'])
				first_run = self.checkpointData.get('first_run', True)

				if first_run:
					self.checkpointData['first_run'] = False

				self.saveCheckpoint()
				qlogger.info("Total time taken to pull the data is %s.", datetime.now()-start)

		except Exception as e:
			qlogger.exception("An error occured while running FIM incidents Populator.")
		qlogger.info("Qualys FIM incidents Populator finished.")



class QualysFimIgnoredEventsPopulator(QualysBaseLogPopulator):
	EXTRA_PARAMS = None

	def _run(self):
		start = datetime.now()
		qlogger.info("Qualys FIM Ignored Events Populator started.")
		try:
			qualysConf = scc.getMergedConf("qualys")

			fim_logger = logging.getLogger('FIM_IGNORED_EVENTS')

			cp_last_run_datetime = None
			fim_events_page_size = int(qualysConf['setupentity'].get('fim_ignored_events_page_size', '1000'))

			fim_configuration = FIMEventsPopulatorConfiguration(fim_logger)
			fim_configuration.events_api_path = "/fim/v2/events/ignore/search"
			fim_configuration.count_api_path = "/fim/v2/events/ignore/count"
			fim_configuration.index = self.INDEX
			fim_configuration.fim_events_page_size = fim_events_page_size
			fim_configuration.source_type = "qualys:fim:ignored_event"
			fim_configuration.event_type = "FIM_IGNORED_EVENT"
			fim_configuration.object_type = "FIM Ignored Event"
			fim_configuration.file_prifix = "fim_ignored_events_list"
			fim_configuration.checkpoint = self.checkpoint
			fim_configuration.checkpointData = self.checkpointData

			#subtract 30 seconds from current time to match the lag of elastic search indexing
			start_time = datetime.utcnow() - timedelta(seconds=30)
			
			cp_last_run_datetime = self.checkpointData.get('last_run_datetime', self.STARTDATE)
			try:
				datetime.strptime(cp_last_run_datetime, '%Y-%m-%dT%H:%M:%S.%fZ')
			except ValueError:		
				cp_last_run_datetime = cp_last_run_datetime[:-1]+".000Z"
				qlogger.info("Checkpoint/Start Date is converted to include milliseconds. Updated value is %s", cp_last_run_datetime)

			qlogger.info("Pulling information about FIM Ignored Events updated after %s", cp_last_run_datetime)
			searchAfter = self.checkpointData.get('searchAfter', [])

			# setting date-time from where to pull the data
			if cp_last_run_datetime is not None:
				fim_configuration.dateTime_start = cp_last_run_datetime
				fim_configuration.dateTime_end = start_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+"Z"

			# setting user-defined extra api parameters
			if 'fim_ignored_events_extra_params' in qualysConf['setupentity'] and qualysConf['setupentity']['fim_ignored_events_extra_params'] != '':
				qlogger.info("Extra FIM Ignored Events api param(s) set by user are: %s",
							 qualysConf['setupentity']['fim_ignored_events_extra_params'])
				self.EXTRA_PARAMS = qualysConf['setupentity']['fim_ignored_events_extra_params']

				# Check extra params for dateTime
				if "dateTime" in self.EXTRA_PARAMS:
					qlogger.warning("dateTime not allowed in FIM Ignored Events extra API parameters."
									"Continuing the API call without extra parameters.")
				else:
					fim_configuration.add_api_filter(self.EXTRA_PARAMS, True)  # True indicates its user-defined

			fim_stream_handler = logging.StreamHandler(stream=sys.stdout)
			fim_events_formatter = logging.Formatter("%(message)s")
			fim_stream_handler.setFormatter(fim_events_formatter)
			fim_logger.addHandler(fim_stream_handler)
			qlogger.info("StreamHandler added to fim_logger.")

			fim_multi_threading_enabled = qualysConf.get('setupentity').get('fim_ignored_events_multi_threading_enabled')
			if fim_multi_threading_enabled and bool_value(fim_multi_threading_enabled):
				if int(qualysConf['setupentity']['fim_ignored_events_num_threads']) > 1:
					qlogger.warning("TA Version 1.6.0 and above do not support multi-threading for FIM.  Old configuration FIM for threading(if any) is ignored.")

			qlogger.info("FIM Populator will run in non-thread mode.")

			# PULL FIM EVENTS
			# get the count of fim events by calling count API
			fetcher = QualysFIMEventsCountFetcher(fim_configuration)
			fetcher.run()
			total_events_count = fetcher.getCount()
			qlogger.info("Count of FIM Ignored-events to be logged: %s", total_events_count)

			total_logged_events = 0
			if total_events_count > 0:
				fimiifcEv = FIMEventsFetchCoordinator(total_events_count, self.EVENT_WRITER,
													  fim_configuration, searchAfter)
				fimiifcEv.coordinate()

				total_logged_events = fimiifcEv.loggedEventsCount
				qlogger.info("FIM logged total Ignored Events=%d", total_logged_events)
			if total_logged_events > 0 :
				#self.checkpointData['last_run_datetime'] = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
				qlogger.info("Updating FIM Ignored Events checkpoint to %s",
							 self.checkpointData['last_run_datetime'])
				first_run = self.checkpointData.get('first_run', True)

				if first_run:
					self.checkpointData['first_run'] = False

				self.saveCheckpoint()
				qlogger.info("Total time taken to pull the data is %s.", datetime.now() - start)
		except Exception as e:
			qlogger.exception("An error occured while running FIM Ignored Events Populator.")
		qlogger.info("Qualys FIM Ignored Events Populator finished.")


class QualysActivityLogPopulator(QualysBaseLogPopulator):
	EXTRA_PARAMS = None

	def _run(self):
		start = datetime.now()
		qlogger.info("Qualys Activity Log Populator started.")
		try:
			qualysConf = scc.getMergedConf("qualys")

			activity_logger = logging.getLogger('ACTIVITY_LOG')

			cp_last_run_datetime = None

			activity_log_configuration = ActivityLogPopulatorConfiguration(activity_logger)
			activity_log_configuration.index = self.INDEX
			activity_log_configuration.host = self.HOST
			activity_log_configuration.source_type = "qualys:activityLogs"
			activity_log_configuration.event_type = "ACTIVITY_LOG"
			activity_log_configuration.object_type = "Activity Log"
			activity_log_configuration.file_prifix = "activity_logs_list"
			activity_log_configuration.checkpoint = self.checkpoint
			activity_log_configuration.checkpointData = self.checkpointData

			start_time = datetime.utcnow()
			
			cp_last_run_datetime = self.checkpointData.get('last_run_datetime', self.STARTDATE)
			qlogger.info("Pulling activity logs data after %s", cp_last_run_datetime)

			# setting date-time from where to pull the data
			if cp_last_run_datetime is not None:
				activity_log_configuration.add_api_filter("since_datetime", cp_last_run_datetime, False)
				activity_log_configuration.add_api_filter("until_datetime", start_time.strftime('%Y-%m-%dT%H:%M:%SZ'), False)

			# setting user-defined extra api parameters
			extra_params = None
			if 'al_extra_params' in self.qualysConf['setupentity'] and self.qualysConf['setupentity']['al_extra_params'] != '':
				qlogger.info("Parsing extra parameter string:%s",
							 self.qualysConf['setupentity']['al_extra_params'])
				try:
					extra_params = json.loads(self.qualysConf['setupentity']['al_extra_params'])
				except ValueError as e:
					qlogger.info("Parameters are not in JSON format, parsing as regular URL params: %s.",
								 self.qualysConf['setupentity']['al_extra_params'])
					extra_params = urlpars.parse_qs(self.qualysConf['setupentity']['al_extra_params'])
					extra_params = dict(map(lambda k_v: (k_v[0], ','.join(k_v[1])), iter(list(extra_params.items()))))

				if extra_params:
					for name in extra_params:
						qlogger.info("Adding Activity log extra param:%s with value: %s", name, extra_params[name])
						activity_log_configuration.add_api_filter(name, extra_params[name], True) # True indicates its user-defined
				else:
					qlogger.error("Error setting extra detection API parameters via string: %s",
								  self.qualysConf['setupentity']['al_extra_params'])

			stream_handler = logging.StreamHandler(stream=sys.stdout)
			formatter = logging.Formatter("%(message)s")
			stream_handler.setFormatter(formatter)
			activity_logger.addHandler(stream_handler)
			qlogger.info("StreamHandler added to activity_logger.")
			
			activityLogger = ActivityLogPopulator(activity_log_configuration, self.EVENT_WRITER)
			activityLogger.run()

			total_logged_events = activityLogger.get_logged_events

			if total_logged_events > 0 :
				qlogger.info("Total logged Activity Log events=%d", total_logged_events)
				#self.checkpointData['last_run_datetime'] = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
				self.checkpointData['last_run_datetime'] = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
				qlogger.info("Updating Activity Log checkpoint to %s",
							 self.checkpointData['last_run_datetime'])
				first_run = self.checkpointData.get('first_run', True)

				if first_run:
					self.checkpointData['first_run'] = False

				self.saveCheckpoint()
				qlogger.info("Total time taken to pull the data is %s.", datetime.now() - start)
		except Exception as e:
			qlogger.exception("An error occured while running Activity Log Populator.")
		qlogger.info("Qualys Activity Log Populator finished.")


class QualysSemDetectionPopulator(QualysBaseLogPopulator):
	def _run(self, configuration_dict=None):
		try:
			detection_logger = logging.getLogger('SEM_DETECTIONS')
			start_time = datetime.utcnow()

			log_individual_sem_detection = bool_value(self.qualysConf['setupentity'].get('log_individual_sem_detection', '1'))
			log_sem_asset_summary = bool_value(self.qualysConf['setupentity'].get('log_sem_asset_summary', '1'))

			cp_last_run_datetime = None

			if log_individual_sem_detection or log_sem_asset_summary:
				sem_detection_configuration = SemDetectionPopulatorConfiguration(detection_logger)
				cp_last_run_datetime = self.checkpointData.get('last_run_datetime', self.STARTDATE)

				qlogger.info("TA will stream events directly into Splunk over stdout.")

				last_fetched_date_time = ''
				if cp_last_run_datetime:
					try:
						detection_updated_before = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
						qlogger.info("Fetching SEM detection data since %s and before %s", cp_last_run_datetime, detection_updated_before)
						last_fetched_date_time = datetime.strptime(cp_last_run_datetime, '%Y-%m-%dT%H:%M:%SZ')
						sem_detection_configuration.add_sem_detection_api_filter('detection_updated_since', cp_last_run_datetime)
						sem_detection_configuration.add_sem_detection_api_filter('detection_updated_before', detection_updated_before)
					except ValueError:
						qlogger.error("Incorrect date format found: %s or %s. The correct date format is: yyyy-mm-ddTHH-MM-SSZ.", cp_last_run_datetime, detection_updated_before)

				# Truncation limit
				sem_detection_configuration.truncation_limit = self.qualysConf['setupentity'].get('sem_truncation_limit', '1000')

				# setup custom SEM detection api parameters
				extra_params = None
				if self.qualysConf['setupentity']['extra_sem_params'] != '':
					extra_sem_params = self.qualysConf['setupentity']['extra_sem_params']

					qlogger.info("Parsing extra detection parameter string:%s",extra_sem_params)

					try:
						extra_params = json.loads(extra_sem_params)
					except ValueError as e:
						qlogger.info("Parameters are not in JSON format, parsing as regular URL params: %s.",
									 extra_sem_params)
						extra_params = urlpars.parse_qs(extra_sem_params)
						extra_params = dict(map(lambda k_v: (k_v[0], ','.join(k_v[1])), iter(list(extra_params.items()))))
					if extra_params:
						for name in extra_params:
							qlogger.info("Adding SEM detection API param:%s with value: %s", name, extra_params[name])
							sem_detection_configuration.add_sem_detection_api_filter(name, extra_params[name], True) # True indicates its user-defined
					else:
						qlogger.error("Error setting SEM extra detection API parameters via string: %s",
									  extra_sem_params)


				sem_detection_configuration.host = self.HOST
				sem_detection_configuration.index = self.INDEX
				sem_detection_configuration.log_individual_sem_detection = log_individual_sem_detection
				sem_detection_configuration.log_sem_asset_summary = log_sem_asset_summary

				try:
					total_logged = 0
					qlogger.info("SEM detection populator will run in non-thread mode.")
					sem_detection_api_populator = SemDetectionPopulator(sem_detection_configuration, self.EVENT_WRITER)
					sem_detection_api_populator.run()
					total_asset_logged = sem_detection_api_populator.get_asset_logged_count

					qlogger.info("Done loading SEM detections for %d assets.", total_asset_logged)

					# store date/time when data pull was started, only if atlease one asset was logged
					# TODO: update checkpoint at this point
					if total_asset_logged > 0:
						self.checkpointData['last_run_datetime'] = detection_updated_before
						qlogger.info("Setting checkpointData last_run_datetime to %s" % self.checkpointData['last_run_datetime'])

						first_run = self.checkpointData.get('first_run', True)
						if first_run:
							self.checkpointData['first_run'] = False

						qlogger.info("Updating checkpoint to %s", self.checkpointData['last_run_datetime'])
						self.saveCheckpoint()

				except BasePopulatorException as e:
					if sys.version_info[0] == 3:
						qlogger.error(e)
					else:
						qlogger.error(e.message)

		except Exception as e:
			qlogger.exception("An error occurred while running SEM Detection Populator.")
		qlogger.info("Qualys SEM Detection Populator finished.")
# end of QualysSemDetectionPopulator class

class QualysPCRSPopulator(QualysBaseLogPopulator):
	def _run(self):
		"""
		:rtype : object
		:type configuration_dict: dict
		:param api_user:
		:param api_password:
		:param configuration_dict:
		"""
		qlogger.info("Qualys PCRS Populator started.")
		try:

			pcrs_logger = logging.getLogger('PCRS_POSTURE_INFO')

			cp_last_run_datetime = None
			evidenceRequired= bool_value(self.qualysConf['setupentity'].get('evidenceRequired', '0'))
			qlogger.info("Add additional field EVIDENCE? %s", evidenceRequired)

			pid_range = range(1, 11)
			pcrs_num_count_for_pid = int(self.qualysConf['setupentity']['pcrs_num_count_for_pid'])
			if pcrs_num_count_for_pid not in pid_range:
				qlogger.warning("Invalid value %s set for number of POLICY IDs. Using default value 2.", pcrs_num_count_for_pid)
				pcrs_num_count_for_pid = 2
			
			qlogger.info("Number of Policy IDs to set in each Resolve Host Ids API call: %s", pcrs_num_count_for_pid)
			
			pcrs_configuration = PCRSPosturePopulatorConfiguration(pcrs_logger)
			pcrs_configuration.host = self.HOST
			pcrs_configuration.index = self.INDEX
			pcrs_configuration.evidenceRequired = evidenceRequired
			pcrs_configuration.pcrs_num_count_for_pid= pcrs_num_count_for_pid
			cp_last_run_datetime = self.checkpointData.get('last_run_datetime', self.STARTDATE)
			qlogger.info("Pulling information about policies updated after %s", cp_last_run_datetime)

			# setting date-time from where to pull the data
			if cp_last_run_datetime:
				pcrs_configuration.add_pcrs_posture_api_filter('status_changes_since', cp_last_run_datetime)

				pcrs_stream_handler = logging.StreamHandler(stream=sys.stdout)
				pcrs_formatter = logging.Formatter("%(message)s")
				pcrs_stream_handler.setFormatter(pcrs_formatter)
				pcrs_logger.addHandler(pcrs_stream_handler)
				qlogger.info("StreamHandler added to pcrs_logger.")

				threads_range= range(2,11)
				num_threads = int(self.qualysConf['setupentity']['pcrs_num_threads'])
				if num_threads not in threads_range:
					qlogger.warning("Invalid value %s set for number of threads. Using default value 2.", num_threads)
					num_threads=2
			
				qlogger.info("PCRS input running in multi-thread mode with %s threads.", num_threads)

				pcrs_coordinator = PCRSPostureInfoFetchCoordinator(num_threads,self.EVENT_WRITER, pcrs_configuration)
				pcrs_coordinator.coordinate()

				total_logged = pcrs_coordinator.get_logged_controls_count
				qlogger.info("PCRS input logged %d entries.", total_logged)

				if total_logged > 0:
					self.checkpointData['last_run_datetime'] = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
					qlogger.info("Updating Policy Compliance Reporting Service checkpoint to %s", self.checkpointData['last_run_datetime'])
					first_run = self.checkpointData.get('first_run', True)

					if first_run:
						self.checkpointData['first_run'] = False

					self.saveCheckpoint()
				
		except Exception as e:
			qlogger.exception("An error occurred while running PCRS Populator.")
		qlogger.info("Qualys PCRS Populator finished.")
	# end of _run()
# end of QualysPCRSPopulator class