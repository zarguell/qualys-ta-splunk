__author__ = 'Qualys, Inc'

from qualysModule import qlogger

import os
import csv
import time
import six.moves.queue as Queue
from threading import Thread, ThreadError, Lock

from qualysModule.splunkpopulator.policypopulator import QualysPolicyPopulator, ThreadedPostureInfoPopulator, PolicyPopulatorConfiguration
import qualysModule.splunkpopulator.utils

class PostureInfoFetchCoordinator:
	appIdQueue = Queue.Queue()
	idChunks = []

	def __init__(self, numThreads, num_count_for_pid, event_writer, posture_configuration):
		self.numThreads = int(numThreads)
		self.postureConfiguration = posture_configuration
		self.loggedControlsCount = 0
		self.lock = Lock()
		self.event_writer = event_writer
		self.num_count_for_pid = int(num_count_for_pid)
	# end of __init__

	def load_posture_info(self, i, control, idsetQueue):
		while True:
			try:
				item = idsetQueue.get(False)
				qlogger.info("Item taken from queue: %s", item)
				qlogger.info("There are approximately %s more items in queue.", idsetQueue.qsize())
				populator = ThreadedPostureInfoPopulator(item, self.event_writer, self.postureConfiguration)
				populator.run()
				total_logged = populator.get_logged_controls_count
				qlogger.info("Logged %d controls." % total_logged)

				if total_logged > 0:
					self.lock.acquire()
					try:
						self.loggedControlsCount += total_logged
					except e:
						qlogger.exception("Exception while updating logged controls count: %s", e)
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
	# end of load_posture_info

	def coordinate(self):
		idsetQueue = Queue.Queue()
		workers = []
		control = {'waitForWork': True}
		i =0
		while (i < self.numThreads):
			th = Thread(target=self.load_posture_info, args=(i, control, idsetQueue,))
			th.setDaemon(True)
			th.start()
			workers.append(th)
			i += 1
		# end of while

		# TODO: Call Policy Info API to get policy details
		policy_configuration = PolicyPopulatorConfiguration(self.postureConfiguration.logger)
		policy_configuration.host = self.postureConfiguration.host
		policy_configuration.index = self.postureConfiguration.index
		policy_configuration.checkpoint_datetime = self.postureConfiguration.get_posture_api_param_value('status_changes_since')

		posture_policy_ids = self.postureConfiguration.get_posture_api_param_value('policy_id')
		if posture_policy_ids:
			policy_configuration.add_policy_api_filter('ids', posture_policy_ids)

		policyPopulator = QualysPolicyPopulator(policy_configuration, idsetQueue, self.event_writer, self.num_count_for_pid)
		policyPopulator.run()

		# now we have got all policy ids in queue. tell threads not to wait anymore if they see queue empty.
		control['waitForWork'] = False

		idsetQueue.join()
		for th in workers:
			th.join()
	# end of coordinate

	@property
	def get_logged_controls_count(self):
		return self.loggedControlsCount
	# end of getLoggedHostsCount
# end of class PostureInfoFetchCoordinator
