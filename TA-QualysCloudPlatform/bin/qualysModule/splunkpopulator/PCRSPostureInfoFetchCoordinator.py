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
import traceback

class PCRSPostureInfoFetchCoordinator:
    appIdQueue = Queue.Queue()
    idChunks = []

    def __init__(self, numThreads, event_writer, pcrs_configuration):
        self.numThreads = int(numThreads)
        self.pcrsConfiguration = pcrs_configuration
        self.loggedControlsCount = 0
        self.lock = Lock()
        self.event_writer = event_writer
        self.hostId_batch_size=pcrs_configuration.hostId_batch_size
        self.pcrs_custom_policy_operation=pcrs_configuration.pcrs_custom_policy_operation
        self.total_logged=0
    
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

                try:
                    for resolved_hosts in host_ids:
                        postureReqBody=[]
                        batched_host_dict={}
                        batched_host_list=[]
                        number_of_hosts=len(resolved_hosts['hostIds'])
                        if 'error' in resolved_hosts:
                            qlogger.error('Policy Id: '+resolved_hosts['policyId']+': '+resolved_hosts['error'])

                        if(len(resolved_hosts['hostIds'])==0):
                            qlogger.info("Skipping Policy Id %s as no hosts were found for this Policy Id.",resolved_hosts['policyId'])

                        else:
                            if(number_of_hosts<self.hostId_batch_size):
                                qlogger.info("Number of host Ids is less than the configured batch size for policy Id %s. Host Ids received for this policy Id are: %s. Sending Host Ids without batching to Streaming API.",resolved_hosts['policyId'],resolved_hosts['hostIds'])
                                batched_host_list.append(resolved_hosts)
                                postureReqBody=batched_host_list
                            
                                postureInfoPopulator=ThreadedPostureInfoPopulator(postureReqBody, self.event_writer, self.pcrsConfiguration)
                                postureInfoPopulator.run()
                                qlogger.info("Logged %d controls." % int(postureInfoPopulator.get_logged_controls_count))
                                self.total_logged+=int(postureInfoPopulator.get_logged_controls_count)
                            else:
                                batch_count=1
                                qlogger.info("Number of host Ids is more than or equal to the configured batch size for policy Id %s. Batching Host Ids.",resolved_hosts['policyId'])
                                while(len(resolved_hosts['hostIds']))!=0:
                                    split_hostIds=resolved_hosts['hostIds'][:self.hostId_batch_size]
                                    batched_host_dict['policyId']=resolved_hosts['policyId']
                                    batched_host_dict['subscriptionId']=resolved_hosts['subscriptionId']
                                    batched_host_dict['hostIds']=split_hostIds
                                    batched_host_list.append(batched_host_dict)
                                    qlogger.info("Sending batch %d to streaming api containing host Ids %s for policy Id %s",batch_count,split_hostIds,resolved_hosts['policyId'])
                                    postureReqBody=batched_host_list
                                
                                    postureInfoPopulator=ThreadedPostureInfoPopulator(postureReqBody, self.event_writer, self.pcrsConfiguration)
                                    postureInfoPopulator.run()
                                    qlogger.info("Logged %d controls." % int(postureInfoPopulator.get_logged_controls_count))
                                    self.total_logged+=int(postureInfoPopulator.get_logged_controls_count)
                                
                                    batched_host_list=[]
                                    resolved_hosts['hostIds']=resolved_hosts['hostIds'][self.hostId_batch_size:]
                                    batch_count+=1
                except Exception as e:
                    qlogger.error("An error occurred while processing JSON Output for Resolve Host Ids API in PCRS Fetch Coordinator. Message: %s :: %s JSON API Output received is: %s",str(e),traceback.format_exc(),host_ids)
                    continue

               
                if self.total_logged > 0:
                    self.lock.acquire()
                    try:
                        self.loggedControlsCount = self.total_logged
                    except e:
                        qlogger.exception("Exception while updating logged controls count. Message: %s :: %s", e, traceback.format_exc())
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
        pcrs_configuration.custom_policy_ids=self.pcrsConfiguration.custom_policy_ids
        pcrs_configuration.pcrs_max_api_retry_count=self.pcrsConfiguration.pcrs_max_api_retry_count
        pcrs_configuration.pcrs_custom_policy_operation=self.pcrsConfiguration.pcrs_custom_policy_operation
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