__author__ = 'Qualys, Inc'

from qualysModule import qlogger

import os
import csv
import time
import six.moves.queue as Queue
from threading import Thread, ThreadError, Lock

from qualysModule.splunkpopulator.pcrspopulator import QualysPCRSPolicyPopulator
from qualysModule.splunkpopulator.pcrspopulator import PCRSPolicyPopulatorConfiguration
from qualysModule.splunkpopulator.pcrspopulator import ThreadedResolveHostIDsPopulator
from qualysModule.splunkpopulator.pcrspopulator import ThreadedPostureInfoPopulator
import qualysModule.splunkpopulator.utils

class PCRSPostureInfoFetchCoordinator:
    appIdQueue = Queue.Queue()
    idChunks = []

    def __init__(self, numThreads, event_writer, pcrs_configuration):
        self.numThreads = int(numThreads)
        self.pcrsConfiguration = pcrs_configuration
        self.loggedControlsCount = 0
        self.lock = Lock()
        self.event_writer = event_writer
    
	# end of __init__ 

    def load_pcrs_posture_info(self, i, control, idsetQueue):
        while True:
            try:
                item=idsetQueue.get(False)
                item=item.replace("[","").replace("]","").replace("'","")
                qlogger.info("Item(s) taken from queue is %s",item)
                qlogger.info("There are approximately %s more items in queue.", idsetQueue.qsize())

                resolveHostIdspopulator=ThreadedResolveHostIDsPopulator(item, self.pcrsConfiguration)
                resolveHostIdspopulator.run()

                host_ids=resolveHostIdspopulator.host_ids_list

                postureInfoPopulator=ThreadedPostureInfoPopulator(host_ids, self.event_writer, self.pcrsConfiguration)
                postureInfoPopulator.run()
                total_logged=int(postureInfoPopulator.get_logged_controls_count)
                qlogger.info("Logged %d controls." % total_logged)

                if total_logged > 0:
                    self.lock.acquire()
                    try:
                        self.loggedControlsCount  += total_logged
                    except e:
                        qlogger.exception("Exception while updating logged controls count:: %s", e)
                    finally:
                        self.lock.release()

                idsetQueue.task_done()
                qlogger.info("Task done.")
                
            except Queue.Empty as e:
                qlogger.info("inbound idsetQueue empty.")
                if control['waitForWork']==False:
                    qlogger.info("inbound queue exiting")
                    break
                else:
                    qlogger.info("inbound idsetQueue waiting for more work.")
                    time.sleep(5)
                    continue

    def coordinate(self):        
        idsetQueue = Queue.Queue()
        workers=[]
        control ={'waitForWork': True}
        i=0
        while(i < self.numThreads):
            th = Thread(target=self.load_pcrs_posture_info, args=(i, control, idsetQueue,))
            th.setDaemon(True)
            th.start()
            workers.append(th)
            i+=1
        #end of while

        #call to policy list api
        pcrs_configuration= PCRSPolicyPopulatorConfiguration(self.pcrsConfiguration.logger)
        pcrs_configuration.host= self.pcrsConfiguration.host
        pcrs_configuration.index= self.pcrsConfiguration.index
        pcrs_configuration.pcrs_num_count_for_pid=self.pcrsConfiguration.pcrs_num_count_for_pid
        pcrs_configuration.checkpoint_datetime= self.pcrsConfiguration.get_pcrs_posture_api_param_value('status_changes_since')        

        pcrsPopulator= QualysPCRSPolicyPopulator(pcrs_configuration, idsetQueue, self.event_writer)
        pcrsPopulator.run()

        control['waitForWork']= False

        idsetQueue.join()
        for th in workers:
            th.join()

        #end of coordinate

    @property
    def get_logged_controls_count(self):
        return self.loggedControlsCount
	# end of getLoggedHostsCount