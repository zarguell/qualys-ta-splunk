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

from qualysModule.splunkpopulator.cspopulator import *
import qualysModule.splunkpopulator.utils

class CsImageFetchCoordinator:
	appIdQueue = Queue.Queue()
	idChunks = []

	def __init__(self, numThreads, event_writer, cs_configuration):
		self.numThreads = int(numThreads)
		self.csImageConfiguration = cs_configuration
		self.loggedVulsCount = 0
		self.total_logged = 0
		self.lock = Lock()
		self.event_writer = event_writer
		self.cs_image_api_extra_parameters = cs_configuration.cs_image_api_extra_parameters
		self.cs_page_size = cs_configuration.cs_image_page_size
	# end of __init__

	def load_cs_image_vulns_info(self, i, control, idsetQueue):
		while True:
			try:
				keyStr = idsetQueue.get(False)
				keyStr = keyStr.replace("\'", "\"")
				item = json.loads(keyStr)
				qlogger.info("New imageSha & uniqueKey taken from queue: %s", item)
				qlogger.info("There are approximately %s more items in queue.", idsetQueue.qsize())
				vulnpopulator = ThreadedCsVulnInfoPopulator(item, self.event_writer, self.csImageConfiguration)				
				vulnpopulator.run()
				total_logged = int(vulnpopulator.get_logged_vulns_count)
				qlogger.info("Logged %d vulnerability/ies." % total_logged)

				if total_logged > 0:
					self.lock.acquire()
					try:
						self.loggedVulsCount += total_logged
					except e:
						qlogger.exception("Exception while updating logged vulns count: %s", e)
					finally:
						self.lock.release()

				idsetQueue.task_done()
				qlogger.info("Task done.")
			except Queue.Empty as e:
				qlogger.info("inbound idsetQueue empty.")
				if control['waitForWork'] == False:
					qlogger.info("inbound queue exiting.")
					break
				else:
					qlogger.info("inbound idsetQueue waiting for more work.")
					time.sleep(5)
					continue
	# end of load_cs_image_vulns_info

	def coordinate(self):
		idsetQueue = Queue.Queue()
		workers = []
		control = {'waitForWork': True}
		i =0

		while (i < self.numThreads):
			th = Thread(target=self.load_cs_image_vulns_info, args=(i, control, idsetQueue,))
			th.setDaemon(True)
			th.start()
			workers.append(th)
			i += 1
		# end of while

		csImagePopulator = QualysCSImagePopulator(self.csImageConfiguration, idsetQueue, self.event_writer)
		csImagePopulator.run()
		self.total_logged = int(csImagePopulator.get_logged_img_count)
		total_count = int(csImagePopulator.get_total_img_count)		
		qlogger.info("Logged %d image/s.", self.total_logged)

		# now we have got all image ids in queue. tell threads not to wait anymore if they see queue empty.
		control['waitForWork'] = False

		idsetQueue.join()
		for th in workers:
			th.join()
	# end of coordinate

	@property
	def get_logged_vulns_count(self):
		return self.loggedVulsCount

	@property
	def get_logged_image_count(self):
		return self.total_logged
	# end of getLoggedHostsCount
# end of class PostureInfoFetchCoordinator
