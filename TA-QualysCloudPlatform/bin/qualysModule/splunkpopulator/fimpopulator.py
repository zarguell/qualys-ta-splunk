__author__ = 'Qualys, Inc'
# -*- coding: utf-8 -*-
__copyright__ = "Copyright (C) 2018, Qualys, Inc"
__license__ = "New BSD"
__version__ = "1.0"

import os
import csv
import time
import json
import six.moves.urllib.request as urlreq, six.moves.urllib.parse as urlpars, six.moves.urllib.error as urlerr
from threading import current_thread

from qualysModule.splunkpopulator.basepopulator_json import BasePopulatorJson, BasePopulatorJsonException
from collections import namedtuple
from qualysModule import qlogger

from qualysModule.splunkpopulator.utils import convertTimeFormat
from threading import current_thread
from qualysModule.lib import api

from qualysModule import *
from lib.splunklib.modularinput import Event
from io import open

class QualysFIMIncidentsCountFetcher(BasePopulatorJson):
	OBJECT_TYPE = "QualysFIMIncidentsCountFetcher"
	FILE_PREFIX = "fim_incidents_count"
	count = 0
	
	def __init__(self, fim_configuration):
		self.fim_configuration = fim_configuration
		super(QualysFIMIncidentsCountFetcher, self).__init__()
	
	@property
	def get_api_parameters(self):
		return ''
	# end of get_api_parameters
	
	@property
	def api_end_point(self):
		try:
			endpoint = "/fim/v2/incidents/count"
			return endpoint
		except:
			return False
	# end of api_end_point

	def getCount(self):
		return int(self.count)

	def run(self):
		response = self._BasePopulatorJson__fetch_and_parse()
		return response

	def getCountParams(self):
		pass
	# end of getIdParams

	def _fetch(self):
		date_range_filter = "createdBy.date: ['%s'..'%s']" % (self.fim_configuration.dateTime_start,self.fim_configuration.dateTime_end)
		api_params = {"filter": date_range_filter}
		if self.fim_configuration.fim_api_extra_parameters not in ("", None):
			api_params["filter"] = self.fim_configuration.fim_api_extra_parameters + " and " + date_range_filter
		api_end_point = self.api_end_point
		if api_end_point:
			filename = temp_directory + "/%s_%s_%s_%s_page_%s.json" % (
				self.FILE_PREFIX, start_time.strftime('%Y-%m-%d-%M-%S'), current_thread().getName(), os.getpid(),
				self._page)
			response = self.api_client.get(api_end_point, api_params, api.Client.XMLFileBufferedResponse(filename))
			return response
		else:
			raise Exception("API endpoint not set, when fetching values for Object type:%", self.OBJECT_TYPE)

	def _process_json_file(self, file_name):
		self.next_batch_url = None
		rawJson = json.load(open(file_name))
		try:
			self.count = rawJson['count']
			qlogger.info("Count of FIM Incidents to be logged: %s", self.count)
		except Exception as e:
			qlogger.error("Could not get Incidents count from API. Reason: " + str(e))
			self.count = 0


class QualysFIMEventsCountFetcher(BasePopulatorJson):
	OBJECT_TYPE = "QualysFIMEventsCountFetcher"
	FILE_PREFIX = "fim_events_count"
	count = 0
	
	def __init__(self, fim_configuration):
		self.fim_configuration = fim_configuration
		super(QualysFIMEventsCountFetcher, self).__init__()
	
	@property
	def get_api_parameters(self):
		return ''
	# end of get_api_parameters
	
	@property
	def api_end_point(self):
		try:
			endpoint = self.fim_configuration.count_api_path
			return endpoint
		except:
			return False
	# end of api_end_point

	def getCount(self):
		return int(self.count)

	def run(self):
		response = self._BasePopulatorJson__fetch_and_parse()
		return response

	def getCountParams(self):
		pass
	# end of getIdParams

	def _fetch(self):
		date_range_filter = "processedTime: ['%s'..'%s']" % (self.fim_configuration.dateTime_start,self.fim_configuration.dateTime_end)
		api_params = {"filter": date_range_filter}
		if self.fim_configuration.fim_api_extra_parameters not in ("", None):
			api_params["filter"] = self.fim_configuration.fim_api_extra_parameters + " and (" + date_range_filter + ")"
		api_end_point = self.api_end_point
		if api_end_point:
			filename = temp_directory + "/%s_%s_%s_%s_page_%s.json" % (
				self.FILE_PREFIX, start_time.strftime('%Y-%m-%d-%M-%S'), current_thread().getName(), os.getpid(),
				self._page)
			response = self.api_client.get(api_end_point, api_params, api.Client.XMLFileBufferedResponse(filename))
			return response
		else:
			raise Exception("API endpoint not set, when fetching values for Object type:%", self.OBJECT_TYPE)

	def _process_json_file(self, file_name):
		self.next_batch_url = None
		rawJson = json.load(open(file_name))
		try:
			self.count = rawJson['count']
		except Exception as e:
			qlogger.error("Could not get events count from API. Reason: " + str(e))
			self.count = 0


class QualysFIMIncidentEventsCountFetcher(BasePopulatorJson):
	OBJECT_TYPE = "QualysFIMEventsCountFetcher"
	FILE_PREFIX = "fim_events_count"
	count = 0
	
	def __init__(self, fim_configuration):
		self.fim_configuration = fim_configuration
		super(QualysFIMIncidentEventsCountFetcher, self).__init__()
	
	@property
	def get_api_parameters(self):
		return ''
	# end of get_api_parameters
	
	@property
	def api_end_point(self):
		try:
			endpoint = self.fim_configuration.count_api_path
			return endpoint
		except:
			return False
	# end of api_end_point

	def getCount(self):
		return int(self.count)

	def run(self):
		response = self._BasePopulatorJson__fetch_and_parse()
		return response

	def getCountParams(self):
		pass
	# end of getIdParams

	def _process_json_file(self, file_name):
		self.next_batch_url = None
		rawJson = json.load(open(file_name))
		try:
			self.count = rawJson['count']
		except Exception as e:
			qlogger.error("Could not get incident events count from API. Reason: " + str(e))
			self.count = 0


class FIMEventsPopulatorConfiguration(object):
	_params_not_allowed = ["dateTime", "processedTime"]

	def __init__(self, logger):
		self.logger = logger
		self.fim_api_extra_parameters = ""
		self.dateTimeLabel = 'dateTime: '
		self.dateTime_start = ""
		self.dateTime_end = ""
		self.fim_events_page_size = 1000
		self.events_api_path = ""
		self.count_api_path = ""
		self.source_type = ""
		self.event_type = ""
		self.object_type = ""
		self.file_prifix = ""

	def add_api_filter(self, extra_params, user_defined=False):
		try:
			qlogger.info("Adding FIM API extra parameter -  %s", extra_params)
			self.fim_api_extra_parameters = extra_params
		except Exception as e:
			qlogger.warning("Exception: FIM API filter - %s", str(e))


"""FIM Events Populator"""
class QualysFIMEventsPopulator(BasePopulatorJson):
	SOURCE = 'qualys'
	HOST = 'localhost'
	INDEX = 'main'
	ROOT_TAG = ""
	FIRST_PAGE = True  # changes to False after first page (page 0) is processed

	def __init__(self, page_no, searchAfter, event_writer, fim_configuration):
		super(QualysFIMEventsPopulator, self).__init__(fim_configuration.logger)
		self.fim_configuration = fim_configuration
		self.LOGGED = 0
		self.INDEX = fim_configuration.index
		self.EVENT_WRITER = event_writer
		self.page_numbers = [0]
		self.total_img_count = 0
		self.page_size = fim_configuration.fim_events_page_size
		self.filter = ""
		self.total_events_count = 0
		self.pageSize = fim_configuration.fim_events_page_size
		self.SOURCETYPE = fim_configuration.source_type
		self.OBJECT_TYPE = fim_configuration.object_type
		self.FILE_PREFIX = fim_configuration.file_prifix
		self.splunk_event_type = fim_configuration.event_type
		self.searchAfter = searchAfter
		self.checkpoint = fim_configuration.checkpoint
		self.lastRecordDate = fim_configuration.dateTime_start
		self.checkpointData = fim_configuration.checkpointData
		self.page_no = page_no


	@property
	def get_searchAfter(self):
		return self.searchAfter

	@property
	def get_logged_events_count(self):
		return self.LOGGED

	@property
	def get_total_events_count(self):
		return self.total_img_count

	@property
	def api_end_point(self):
		"""
		we add API params in this method to allow GET request be made.
		"""
		try:
			endpoint = self.fim_configuration.events_api_path
			return endpoint
		except:
			return False


	def _fetch(self):
		date_range_filter = "processedTime: ['%s'..'%s']" % (self.fim_configuration.dateTime_start, self.fim_configuration.dateTime_end)
		api_params = {"filter": date_range_filter, "sort": '[{"processedTime":"asc"}, {"id":"asc"}]', "pageSize": str(self.pageSize), "searchAfter": self.searchAfter}
		if self.fim_configuration.fim_api_extra_parameters not in ("", None):
			api_params["filter"] = self.fim_configuration.fim_api_extra_parameters + " and (" + date_range_filter + ")"
		api_end_point = self.api_end_point
		if api_end_point:
			if len(self.searchAfter) > 0:
				filename = temp_directory + "/%s_%s_%s_%s_fim_events_page_%s.json" % (self.FILE_PREFIX, start_time.strftime('%Y-%m-%d-%M-%S'), current_thread().getName(), os.getpid(), self.searchAfter[0])
			else:
				filename = temp_directory + "/%s_%s_%s_%s_fim_events_page_0.json" % (self.FILE_PREFIX, start_time.strftime('%Y-%m-%d-%M-%S'), current_thread().getName(), os.getpid())
			response = self.api_client.get(api_end_point, api_params, api.Client.XMLFileBufferedResponse(filename))
			return response
		else:
			raise Exception("API endpoint not set, when fetching values for Object type:%s", self.OBJECT_TYPE)

	def _parse(self, file_name):
		qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Started', self.OBJECT_TYPE, file_name)
		try:
			self._pre_parse()
			self._process_json_file(file_name)
			self._post_parse()
		except Exception as e:
			qlogger.error("Failed to parse JSON API Output for endpoint %s. Message: %s", self.api_end_point, str(e))
		finally:
			qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Completed', self.OBJECT_TYPE, file_name)
			return {}
	#End of _parse

	def _process_json_file(self, file_name):
		rawJson = None
		with open(file_name) as read_file:
			rawJson = json.load(read_file)
		try:
			if len(rawJson):
				for fim_event in rawJson:
					event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SOURCETYPE)
					fim_event['data']['splunk_event_type'] = self.splunk_event_type
					event.data = json.dumps(fim_event.get("data"))
					self.EVENT_WRITER.write_event(event)
					self.LOGGED += 1
				self.searchAfter = fim_event.get("sortValues")
				processedTime = fim_event.get("data").get("processedTime")
				self.checkpointData['last_run_datetime'] = processedTime.split("+")[0] + "Z"
				self.checkpointData['searchAfter'] = self.searchAfter
			#if self.page_no != 0 and self.page_no % 10 == 0:
			#Save checkpoint after every page;
			self.saveCheckpoint()
			qlogger.info("Updating FIM Events Information checkpoint to %s"%(self.checkpointData))
			return True
		except Exception as e:
			qlogger.error("Could not process %s element. Error: %s", self.ROOT_TAG, str(e))
			return False
			

"""FIM Incidents Populator"""
class QualysFIMIncidentsPopulator(BasePopulatorJson):
	OBJECT_TYPE = "FIM Incident"
	FILE_PREFIX = "fim_incidents_list"
	SOURCE = 'qualys'
	SOURCETYPE = 'qualys:fim:incident'
	HOST = 'localhost'
	INDEX = 'main'
	ROOT_TAG = ""

	def __init__(self, pageNumber, fim_configuration, incident_ids, event_writer, incident_dateTime):
		super(QualysFIMIncidentsPopulator, self).__init__(fim_configuration.logger)
		self.fim_configuration = fim_configuration
		self.LOGGED = 0
		self.INDEX = fim_configuration.index
		self.EVENT_WRITER = event_writer
		self.filter = ""
		self.total_events_count = 0
		self.pageSize = fim_configuration.fim_events_page_size
		self.incident_ids = incident_ids
		self.pageNumber = pageNumber
		self.incident_dateTime = incident_dateTime


	@property
	def get_logged_incidents_count(self):
		return self.LOGGED

	@property
	def api_end_point(self):
		"""
		we add API params in this method to allow GET request be made.
		"""
		try:
			endpoint = "/fim/v2/incidents/search"
			return endpoint
		except:
			return False

	def _fetch(self):
		date_range_filter = "createdBy.date: ['%s'..'%s']" % (self.fim_configuration.dateTime_start,self.fim_configuration.dateTime_end)
		api_params = {"filter": date_range_filter, "pageSize": str(self.pageSize), "pageNumber": str(self.pageNumber)}
		api_end_point = self.api_end_point
		if api_end_point:
			filename = temp_directory + "/%s_%s_%s_%s_fim_incidents_page_%s.json" % (self.FILE_PREFIX, start_time.strftime('%Y-%m-%d-%M-%S'), current_thread().getName(), os.getpid(), self.pageNumber)
			response = self.api_client.get(api_end_point, api_params, api.Client.XMLFileBufferedResponse(filename))
			return response
		else:
			raise Exception("API endpoint not set, when fetching values for Object type:%", self.OBJECT_TYPE)

	def _parse(self, file_name):
		response = {}
		qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Started', self.OBJECT_TYPE, file_name)
		try:
			self._pre_parse()
			self._process_json_file(file_name)
			self._post_parse()
		except Exception as e:
			qlogger.error("Failed to parse JSON API Output for endpoint %s. Message: %s", self.api_end_point, str(e))
		finally:
			qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Completed', self.OBJECT_TYPE, file_name)
			return response
	#End of _parse

	def _process_json_file(self, file_name):
		rawJson = None
		with open(file_name) as read_file:
			rawJson = json.load(read_file)
		
		try:
			if len(rawJson):
				for fim_event in rawJson:
					fim_event['splunk_event_type'] = "FIM_INCIDENT"
					incident_id = fim_event['id']
					createdBy_utc = convertTimeFormat(str(fim_event.get("createdBy").get("date")))
					#Convert epoch time to zolo datetime
					self.incident_dateTime.update({incident_id: createdBy_utc[:-1]+".000Z"})
					fim_event["createdBy"]["date"] = createdBy_utc
					#self.idsetQueue.put(incident_id)
					self.incident_ids.append(incident_id)
					event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SOURCETYPE)
					event.data = json.dumps(fim_event)
					self.EVENT_WRITER.write_event(event)
					self.LOGGED += 1

			return True
		except Exception as e:
			qlogger.error("Could not process %s element. Error: %s", self.ROOT_TAG, str(e))
			return False
			
			
"""FIM Incidents Populator"""
class ThreadedIncidentEventsPopulator(BasePopulatorJson):
	OBJECT_TYPE = "FIM Incident Event"
	FILE_PREFIX = "fim_incidents_events_list"
	SOURCE = 'qualys'
	SOURCETYPE = 'qualys:fim:incident_event'
	HOST = 'localhost'
	INDEX = 'main'
	ROOT_TAG = ""

	def __init__(self, incident_id, event_writer, fim_configuration, searchAfter, incident_dateTime, last_page):
		super(ThreadedIncidentEventsPopulator, self).__init__(fim_configuration.logger)
		self.fim_configuration = fim_configuration
		self.LOGGED = 0
		self.INDEX = fim_configuration.index
		self.EVENT_WRITER = event_writer
		self.filter = ""
		self.total_events_count = 0
		self.pageSize = fim_configuration.fim_events_page_size
		self.searchAfter = searchAfter
		self.incident_id = incident_id
		self.checkpoint = fim_configuration.checkpoint
		self.lastRecordDate = incident_dateTime
		self.checkpointData = fim_configuration.checkpointData
		self.last_page = last_page

	@property
	def get_logged_incidents_events_count(self):
		return self.LOGGED

	@property
	def api_end_point(self):
		"""
		we add API params in this method to allow GET request be made.
		"""
		try:
			endpoint = "/fim/v2/incidents/"+ self.incident_id +"/events/search"
			return endpoint
		except Exception as e:
			qlogger.error("Exception while makin API path : %s", str(e))
			return False

	def _fetch(self):
		api_params = {"pageSize": str(self.pageSize), "sort": '[{"dateTime":"asc"}, {"id":"asc"}]', "searchAfter": self.searchAfter}
		api_end_point = self.api_end_point
		if api_end_point:
			if len(self.searchAfter) > 0:
				filename = temp_directory + "/%s_%s_%s_%s_fim_incidents_page_%s.json" % (
					self.FILE_PREFIX, start_time.strftime('%Y-%m-%d-%M-%S'), current_thread().getName(), os.getpid(), self.searchAfter[0])
			else:
				filename = temp_directory + "/%s_%s_%s_%s_fim_incidents_page_0.json" % (
					self.FILE_PREFIX, start_time.strftime('%Y-%m-%d-%M-%S'), current_thread().getName(), os.getpid())
			response = self.api_client.get(api_end_point, api_params, api.Client.XMLFileBufferedResponse(filename))
			return response
		else:
			raise Exception("API endpoint not set, when fetching values for Object type:%", self.OBJECT_TYPE)

	def _parse(self, file_name):
		response = {}
		qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Started', self.OBJECT_TYPE, file_name)
		try:
			self._pre_parse()
			self._process_json_file(file_name)
			self._post_parse()
		except Exception as e:
			qlogger.error("Failed to parse JSON API Output for endpoint %s. Message: %s", self.api_end_point, str(e))
		finally:
			qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Completed', self.OBJECT_TYPE, file_name)
			return response
	#End of _parse

	def _process_json_file(self, file_name):
		rawJson = None
		with open(file_name) as read_file:
			rawJson = json.load(read_file)
		
		try:
			if len(rawJson):
				for fim_event in rawJson:
					fim_event['data']['splunk_event_type'] = "FIM_INCIDENT_EVENT"
					event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SOURCETYPE)
					event.data = json.dumps(fim_event.get("data"))
					self.EVENT_WRITER.write_event(event)
					self.LOGGED += 1
				self.searchAfter = fim_event.get("sortValues")
			if self.last_page:
				self.checkpointData['last_run_datetime'] = self.lastRecordDate
				self.saveCheckpoint()
				qlogger.info("Updating FIM Incident Events Information checkpoint to %s"%(self.lastRecordDate))
			return True
		except Exception as e:
			qlogger.error("Could not process %s element. Error: %s", self.ROOT_TAG, str(e))
			return False
