__author__ = 'Prabhas Gupte'

import time
import six.moves.queue as Queue
import copy
from threading import Thread, ThreadError, Lock
from threading import current_thread

from qualysModule import qlogger
from qualysModule.splunkpopulator.webapp import webAppIdFetcher
from qualysModule.splunkpopulator.detectionpopulator import *
import qualysModule.splunkpopulator.utils

class ThreadedWASDetectionPopulator(WASDetectionPopulator):
	idsDict = {}

	def __init__(self, ids, event_writer, detectionConfiguration):
		super(ThreadedWASDetectionPopulator, self).__init__(detectionConfiguration, event_writer)
		currentThreadName = current_thread().getName()
		qlogger.debug("Starting thread %s" % currentThreadName)

		if currentThreadName not in self.idsDict:
			self.idsDict[currentThreadName] = ids
	# end of __init__

	@property
	def get_api_parameters(self):
		currentThreadName = current_thread().getName()
		self.detectionConfiguration.add_detection_api_filter('webApp.id', 'IN', ','.join(self.idsDict[currentThreadName]))

		return self.detectionConfiguration.detection_api_filters
	# get_api_parameters

	def get_next_batch_params(self, lastId):
		currentThreadName = current_thread().getName()
		self.detectionConfiguration.add_detection_api_filter('webApp.id', 'IN', ','.join(self.idsDict[currentThreadName]))
		self.detectionConfiguration.add_detection_api_filter('id', 'GREATER', str(lastId))

		return self.detectionConfiguration.detection_api_filters
	# get_next_batch_params
# end of class ThreadedWASDetectionPopulator

class WASFindingsFetchCoordinator:
	appIdQueue = Queue.Queue()
	idChunks = []

	def __init__(self, numThreads, detectionConfiguration, event_writer):
		self.numThreads = int(numThreads)
		self.detectionConfiguration = detectionConfiguration
		self.loggedHostsCount = 0
		self.lock = Lock()
		self.event_writer = event_writer
	# end of __init__

	def getWebAppIds(self):
		fetcher = webAppIdFetcher(self.appIdQueue)
		fetcher.run()
		ids = fetcher.getIds()
		#sort ids
		ids.sort(key=int)

		numIds = len(ids)
		if numIds == 0:
			qlogger.debug("No web app ids found. Nothing to fetch.")
			return
		# if

		idChunks = qualysModule.splunkpopulator.utils.chunks(ids, self.numThreads)
		idChunksList = list(idChunks)
		finalIdChunksList = list(filter(None, idChunksList))
		numChunks = len(finalIdChunksList)
        
		if numChunks < self.numThreads:
			qlogger.info("Fewer threads are required to process the webAppIds than configured %d threads", self.numThreads)
			self.numThreads = numChunks
			qlogger.info("Using %d threads in multi-thread mode to process the data", self.numThreads)

		for idChunk in finalIdChunksList:
			self.idChunks.append(idChunk)
	# end of getWebAppIds

	def loadWasFindings(self, idChunk):
		dc = None
		dc = copy.copy(self.detectionConfiguration)
		# dc.add_detection_api_filter('webApp.id', 'IN', ','.join(idChunk))
		populator = ThreadedWASDetectionPopulator(idChunk, self.event_writer, dc)
		populator.run()
		total_logged = populator.get_host_logged_count

		if total_logged > 0:
			self.lock.acquire()
			try:
				self.loggedHostsCount += total_logged
			except e:
				qlogger.error(e)
			finally:
				self.lock.release()
			# end of try-except-finally
		# end of if
	# end of loadWasFindings

	def coordinate(self):
		self.getWebAppIds()
		workers = []
		if self.idChunks:
			i =0
			while (i < self.numThreads):
				# qualysModule.splunkpopulator.utils.printStreamEventXML("_internal","Starting thread %d" % i)
				th = Thread(target=self.loadWasFindings, args=(self.idChunks[i],))
				th.setDaemon(True)
				th.start()
				workers.append(th)
				i += 1
			# end of while

			for th in workers:
				th.join()
	# end of coordinate

	def getLoggedHostsCount(self):
		return self.loggedHostsCount
	# end of getLoggedHostsCount
# end of class WASFindingsFetchCoordinator
