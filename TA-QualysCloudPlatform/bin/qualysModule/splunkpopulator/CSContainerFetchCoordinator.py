__author__ = 'Qualys, Inc'
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


class CsContainerFetchCoordinator:
    appIdQueue = Queue.Queue()
    idChunks = []
    unique_containers_set = set()
    null_containers_count = 0

    def __init__(self, event_writer, cs_configuration):
        self.numThreads = int(cs_configuration.num_threads)
        self.cs_configuration = cs_configuration
        self.loggedVulsCount = 0
        self.loggedContainersCount = 0
        self.lock = Lock()
        self.event_writer = event_writer

    # end of __init__

    def load_container_vulns(self, i, control, idsetQueue):
        while True:
            try:
                containerSha = idsetQueue.get(False)  # we get container id from this queue
                qlogger.info("Container sha taken from queue: %s", containerSha)
                qlogger.info("There are approximately %s more items in queue.", idsetQueue.qsize())
                vulnpopulator = ThreadedContainerVulnInfoPopulator(containerSha, self.event_writer,
                                                                   self.cs_configuration)
                vulnpopulator.run()
                total_logged = int(vulnpopulator.get_logged_vulns_count)
                qlogger.info("Logged %d vulnerabilities." % total_logged)

                if total_logged > 0:
                    self.lock.acquire()
                    try:
                        self.loggedVulsCount += total_logged
                    except e:
                        qlogger.exception("Exception while updating logged vulns count: %s", e)
                    finally:
                        self.lock.release()

                self.loggedContainersCount += 1
                self.unique_containers_set.add(containerSha)

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
        i = 0

        while (i < self.numThreads):
            th = Thread(target=self.load_container_vulns, args=(i, control, idsetQueue,))
            th.setDaemon(True)
            th.start()
            workers.append(th)
            i += 1
        # end of while

        containerPopulator = QualysContainerPopulator(self.cs_configuration, idsetQueue, self.event_writer)
        containerPopulator.run()
        # total_logged = int(containerPopulator.get_logged_containers_count)
        total_count = int(containerPopulator.get_total_containers_count)
        qlogger.info("Details will  be downloaded for %d containers.", total_count)
        self.null_containers_count = containerPopulator.get_null_containers_count

        # now we have got all container ids in queue. tell threads not to wait anymore if they see queue empty.
        control['waitForWork'] = False

        idsetQueue.join()
        for th in workers:
            th.join()

    # end of coordinate

    @property
    def get_logged_vulns_count(self):
        return self.loggedVulsCount

    # end of getLoggedHostsCount

    @property
    def get_logged_containers_count(self):
        return self.loggedContainersCount

    @property
    def get_unique_containers_count(self):
        return len(self.unique_containers_set)

    @property
    def get_null_containers_count(self):
        return self.null_containers_count
# end of class PostureInfoFetchCoordinator
