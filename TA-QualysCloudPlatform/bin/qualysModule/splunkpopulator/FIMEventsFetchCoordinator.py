
from qualysModule import qlogger

import os
import csv
import time
import six.moves.queue as Queue
from threading import Thread, ThreadError, Lock

from qualysModule.splunkpopulator.fimpopulator import *
import qualysModule.splunkpopulator.utils
from six.moves import range

class FIMEventsFetchCoordinator:
	appIdQueue = Queue.Queue()
	idChunks = []

	def __init__(self, total_events_count, event_writer, fim_configuration, searchAfter):
		self.total_events_count = total_events_count
		self.fimEventsConfiguration = fim_configuration
		self.loggedEventsCount = 0
		self.total_logged = 0
		self.lock = Lock()
		self.event_writer = event_writer
		self.fim_api_extra_parameters = fim_configuration.fim_api_extra_parameters
		self.fim_page_size = fim_configuration.fim_events_page_size
		self.searchAfter = searchAfter
	# end of __init__

	def coordinate(self):
		total_calls_required, remainder = divmod(self.total_events_count, self.fim_page_size)
		if remainder: total_calls_required += 1
		qlogger.info("Total number of pages to fetch: ~%s"%(total_calls_required))
		for i in range(total_calls_required):
			qlogger.info("Getting Events from page number: %s"%(str(i)))
			fimpopulator = QualysFIMEventsPopulator(i, self.searchAfter, self.event_writer, self.fimEventsConfiguration)
			fimpopulator.run()
			total_logged = int(fimpopulator.get_logged_events_count)

			try:
				self.loggedEventsCount += total_logged
			except Exception as e:
				qlogger.exception("Exception while updating logged events count: %s", e)

			qlogger.info("Till Now Logged FIM events: %s" % (self.loggedEventsCount) )
			self.searchAfter = fimpopulator.get_searchAfter
		qlogger.info("Task done.")
