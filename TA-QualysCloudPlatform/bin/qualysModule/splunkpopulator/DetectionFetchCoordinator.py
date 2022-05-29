__author__ = 'mwirges'

from qualysModule import qlogger
from qualysModule.splunkpopulator.assethost import HostIdRetriever
from qualysModule.splunkpopulator.detectionpopulator import HostDetectionPopulator

import time
import six.moves.queue as Queue
from threading import Thread, ThreadError, Lock
from six.moves import range

"""
Implementation of HostIdRetriever which takes retrieved Ids and puts them
into a fifo queue for processing.
"""


class HostIdsFifoPopulator(HostIdRetriever):
	"""
	:type fifoQueue: Queue.Queue
	"""
	fifoQueue = None

	def __init__(self, fifoQueue, detection_truncation_limit, default_host_truncation_limit, cp_last_run_datetime):
		super(HostIdsFifoPopulator, self).__init__()

		assert isinstance(fifoQueue, Queue.Queue)
		self.fifoQueue = fifoQueue
		self.detection_truncation_limit = detection_truncation_limit
		self.default_host_truncation_limit = default_host_truncation_limit
		self.cp_last_run_datetime = cp_last_run_datetime

	# end __init__

	def _handle_idset(self, idset):
		self.fifoQueue.put(idset)

		# end of for loop


"""
Implementation of the HostDetectionPopulator which, given an explicit IDSet of
host ids, loads detection information.  Optionally it can pipe output to an
output queue.
"""


class ThreadedHostDetectionPopulator(HostDetectionPopulator):
	outboundQueue = None
	ids = None

	def __init__(self, ids, event_writer, hostDetectionConfiguration=None, outboundQueue=None):
		super(ThreadedHostDetectionPopulator, self).__init__(hostDetectionConfiguration, event_writer)
		self.outboundQueue = outboundQueue
		self.ids = ids

	def output(self, log, *args, **kwargs):
		if self.outboundQueue is not None:
			self.outboundQueue.put(log)
		else:
			super(ThreadedHostDetectionPopulator, self).output(log, *args, **kwargs)
			# end if

	@property
	def get_api_parameters(self):
		params = super(ThreadedHostDetectionPopulator, self).get_api_parameters
		#del params['truncation_limit']
		params['ids'] = self.ids

		return params


class DetectonFetchCoordinator:
	config = {}

	detectionWorkers = []

	kbpopulator = None
	logger = None

	def __init__(self, config, hostDetectionConfiguration, event_writer):
		# for now , we're just going to get a dict of config vals until this can be refactored
		self.config = config
		self.hostDetectionConfiguration = hostDetectionConfiguration
		self.host_logged = 0
		self.lock = Lock()
		self.event_writer = event_writer


	@property
	def get_host_logged_count(self):
		return self.host_logged

	# end __init__

	def handleOutput(self, control, outBoundQueue):
		"""
		It is possible to have the detection API output get piped into another queue,
		and this would be a serial way to process the detections.  However, since the
		loggin facility in python is used for writing out data to splunk, and it is
		thread-safe, there's practically no need for it.

		:param control:
		:param outBoundQueue:
		:return:
		"""

		while True:
			try:
				qlogger.info("getting output item")
				item = outBoundQueue.get(False)
				qlogger.info("Output Thread: %s", item)
				outBoundQueue.task_done()
			except Queue.Empty as e:
				if control['out_active'] == False:
					qlogger.info("output thread exiting")
					break
				else:
					qlogger.info("output thread waiting for work")
					time.sleep(5)
					continue
					#end if
					#end try
					#end while

	#end handleOutput

	def loadDetections(self, id, control, idsetQueue, outBoundQueue=None):
		"""
		:param id: int
		:param control: dict
		:param idsetQueue: Queue.Queue
		:param outBoundQueue: Queue
		:return:
		"""

		#TODO make this a thread object

		while True:
			"""
			:type item: IDSet
			"""
			try:
				qlogger.info("getting idset inbound queue...")
				item = idsetQueue.get(False)
				# do something
				qlogger.info("processing idset: %s", item)
				qlogger.info("There are approximately %s more items in queue.", idsetQueue.qsize())

				thdp = ThreadedHostDetectionPopulator(item, self.event_writer, self.hostDetectionConfiguration, outBoundQueue)
				thdp.run()
				if thdp.get_host_logged_count > 0:
					self.lock.acquire()
					try:
						self.host_logged += thdp.get_host_logged_count
					except e:
						qlogger.error("Exception in thdp.host_logged: %s", e)
					finally:
						self.lock.release()

				#outBoundQueue.put(item.tostring())
				idsetQueue.task_done()
			except Queue.Empty as e:
				qlogger.info("inboundqueue empty")
				if control['active'] == False:
					qlogger.info("inbound queue exiting")
					break
				else:
					qlogger.info("waiting for more work")
					time.sleep(5)
					continue
					#end if
					#end

	#end loadDetections

	def coordinate(self):
		idsetQueue = Queue.Queue()
		#outboundQueue = Queue.Queue()

		# logic here is more or less simple, we have a pool of threads of size T
		# load them up, and they sit on the queue, until they are signaled not
		# to expect anything else; then exit

		control = {"active": True, "out_active": True}
		for i in range(self.config['num_threads']):
			qlogger.info("starting thread %d" % (i))
			th = Thread(target=self.loadDetections, args=(i, control, idsetQueue))
			th.setDaemon(True)
			th.start()
			self.detectionWorkers.append(th)
		#end for

		# for reference
		#outputProcessor = Thread(target=self.handleOutput, args=(control, outboundQueue))
		#outputProcessor.setDaemon(True)
		#outputProcessor.start()

		# now we drive with assethost stuff
		qlogger.debug("Doing AssetHost Stuff")
		hip = HostIdsFifoPopulator(idsetQueue, self.hostDetectionConfiguration.truncation_limit, self.hostDetectionConfiguration.default_host_truncation_limit, self.config['cp_last_run_datetime'])
		hip.run()
		qlogger.debug("Done with hostassets, set to false")
		control['active'] = False
		# clean up the queue, clean up the threads
		idsetQueue.join()
		for th in self.detectionWorkers:
			th.join()

			#control['out_active'] = False
			#outboundQueue.join()
			#outputProcessor.join()

			#end coordinate