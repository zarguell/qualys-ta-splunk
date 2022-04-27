# -*- coding: utf-8 -*-
__author__ = "Qualys, Inc"
__copyright__ = "Copyright (C) 2018, Qualys, Inc"
__license__ = "New BSD"
__version__ = "1.0"

from qualysModule import qlogger

import os
import csv
import time
import six.moves.queue as Queue
from threading import Thread, ThreadError, Lock

from qualysModule.splunkpopulator.fimpopulator import *
import qualysModule.splunkpopulator.utils
from six.moves import range

class FIMIncidentsFetchCoordinator:
	appIdQueue = Queue.Queue()
	idChunks = []

	def __init__(self, total_incidents_count, event_writer, fim_configuration):
		self.total_incidents_count = total_incidents_count
		self.fim_configuration = fim_configuration
		self.loggedIncidentsCount = 0
		self.total_logged = 0
		self.lock = Lock()
		self.event_writer = event_writer
		self.fim_api_extra_parameters = fim_configuration.fim_api_extra_parameters
		self.fim_page_size = fim_configuration.fim_events_page_size
		self.pageSize = fim_configuration.fim_events_page_size
	# end of __init__


	def coordinate(self):
		incident_total_pagenumbers, remainder = divmod(self.total_incidents_count, self.pageSize)
		if remainder: incident_total_pagenumbers += 1
		qlogger.info("Total number of incident pages to fetch: %s"%(incident_total_pagenumbers))
		for incident_page_number in range(incident_total_pagenumbers):
			incident_ids = []
			incident_dateTime = {}
			qlogger.info("Getting Incidents from page number: %s"%(incident_page_number))
			incidentsPopulator = QualysFIMIncidentsPopulator(incident_page_number, self.fim_configuration, incident_ids, self.event_writer, incident_dateTime)
			incidentsPopulator.run()
			incident_ids = incidentsPopulator.incident_ids
			incident_dateTime = incidentsPopulator.incident_dateTime
			self.loggedIncidentsCount = incidentsPopulator.get_logged_incidents_count
			qlogger.info("Logged %d Incidents." % self.loggedIncidentsCount)

			for incident in incident_ids:
				self.fim_configuration.count_api_path = "/fim/v2/incidents/"+ incident +"/events/count"
				fetcher = QualysFIMIncidentEventsCountFetcher(self.fim_configuration)
				fetcher.run()
				total_incidents_events_count = fetcher.getCount()
				qlogger.info("Incident ID: %s count of FIM Incident-events to be logged: %s"%(incident, total_incidents_events_count))

				incident_events_total_pagenumbers, remainder = divmod(total_incidents_events_count, self.pageSize)
				if remainder: incident_events_total_pagenumbers += 1
				searchAfter = []
				qlogger.info("Total number of incident events pages to fetch: %s"%(incident_events_total_pagenumbers))

				for incident_event_page_number in range(incident_events_total_pagenumbers):
					qlogger.info("Getting Incident-events from page number: %s for icident: %s"%(incident_event_page_number, incident))
					last_page = False
					if incident_event_page_number == list(range(incident_events_total_pagenumbers))[-1:][0]:
						last_page = True
					populator = ThreadedIncidentEventsPopulator(incident, self.event_writer, self.fim_configuration, searchAfter, incident_dateTime.get(incident), last_page)
					populator.run()
					total_logged = populator.get_logged_incidents_events_count
					searchAfter = populator.searchAfter
					qlogger.info("Logged %d Incidents-events for incident_id: %s", total_logged, incident)

	# end of coordinate
