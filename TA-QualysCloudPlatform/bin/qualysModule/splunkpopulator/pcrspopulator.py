# __author__ = 'Qualys, Inc'

import os
import csv
import sys
import time
import json
import six.moves.urllib.request as urlreq, six.moves.urllib.parse as urlpars, six.moves.urllib.error as urlerr
from threading import current_thread
from qualysModule import qlogger

from qualysModule.splunkpopulator.basepopulator_json import BasePopulatorJson, BasePopulatorJsonException
from collections import namedtuple
from qualysModule.splunkpopulator.utils import convertTimeFormat, bool_value

from qualysModule.lib import api

from qualysModule import *
from lib.splunklib.modularinput import Event
from io import open
import six
import abc
import qualysModule
import math

import zlib
import six.moves.urllib.request as urlreq
import requests
import urllib3
from requests.exceptions import Timeout
import traceback

import re
from requests.auth import HTTPProxyAuth

class PCRSPolicyPopulatorConfiguration(object):
    def __init__(self,logger):
        self.logger= logger
        self.retrycount=0

class PCRSPosturePopulatorConfiguration(PCRSPolicyPopulatorConfiguration):
    def __init__(self,logger):
        self.logger= logger
        self.evidenceRequired = False
        self.evidenceTruncationLimit = 0
        self.pcrs_posture_api_parameters = {}
        self.last_scan_date_resolveHostId = 0
        self.last_scan_date_postureAPI = 1
        self.retrycount=0

    #to get posture info since last checkpoint date
    def add_pcrs_posture_api_filter(self,name,value):
        qlogger.info("Adding PCRS Posture Info API extra parameter %s with value %s", name,value)
        self.pcrs_posture_api_parameters[name]=value

    def get_pcrs_posture_api_param_value(self, param_name):
        if param_name in self.pcrs_posture_api_parameters:
            return self.pcrs_posture_api_parameters[param_name]
        else:
            return None

class PCRSBasePopulatorJson(BasePopulatorJson):

    def run(self):
        response = self.__fetch_and_parse()
        return response              

    def __fetch_and_parse(self):
        while (self.retrycount <= self.pcrs_max_api_retry_count) or (self.pcrs_max_api_retry_count==0):
            try:
                retry_interval = int(self.api_client._config.retry_interval) if self.api_client._config.retry_interval else 300 
                response = self._fetch()
                
                if response!= None:
                    if response.response_code == 204:
                        qlogger.warning("No contents matching given request.")
                        break
                    
                    res_str=bytes(response.get_response()).decode()

                    response_status=res_str

                    if response_status == None or response_status=='' :
                        qlogger.error("Error during Fetching, Cleaning up and retrying")
                        try:
                            time.sleep(3)
                            continue
                        except OSError:
                            pass

                    qlogger.info("%s fetched", self.OBJECT_TYPE)

                    parseresponse = self._parse(res_str)

                    if parseresponse:
                        qlogger.error("An error while fetching and parsing the API response. Retry count %s.", self.retrycount-1)
                        continue
                    else:
                        break

            except Exception as e:
                self.retrycount += 1
                import traceback
                qlogger.debug("Exception while fetching or parsing. %s :: %s", str(e), traceback.format_exc())
                if 'operation timed out' in six.text_type(e):
                    qlogger.error("Timeout while fetching, Retrying %s", e)
                else:
                    import traceback
                    qlogger.error("Exception while fetching or parsing. %s :: %s", str(e), traceback.format_exc())
                continue
        # endwhile
        if self.retrycount >= self.pcrs_max_api_retry_count and self.pcrs_max_api_retry_count!=0:
            if '/posture/hostids' in self.api_end_point :            
                qlogger.info("Maximum retry limit %s has reached. So skipping the following policy ids %s endpoint %s ",self.pcrs_max_api_retry_count,self.ids,self.api_end_point)
            else :
                qlogger.info("Maximum retry limit %s has reached. So skipping the following endpoint %s ",self.pcrs_max_api_retry_count,self.api_end_point)
        return response        
    
    def _fetch(self):
        
        api_params= {}
        api_end_point = self.api_end_point
        if api_end_point:
            response=self.api_client.get(api_end_point, api_params, api.Client.SimpleAPIResponse())
            return response
        else:
            raise Exception("API endpoint not set, when fetching values for Object type:%", self.OBJECT_TYPE)

    # end of PCRSBasePopulatorJson          

#QualysPCRSPolicyPopulator started
class QualysPCRSPolicyPopulator(PCRSBasePopulatorJson):
    OBJECT_TYPE = "Policy Compliance Reporting Service"
    SOURCE = 'qualys'
    SOURCETYPE = 'qualys:pcrs:policyInfo'
    HOST = 'localhost'
    INDEX = 'main'
    BASE_ENDPOINT="/pcrs/1.0/posture/policy/list"

    def __init__(self, pcrs_configuration, pcrs_idset_queue, event_writer):
        super(QualysPCRSPolicyPopulator, self).__init__(pcrs_configuration.logger)
        self.pcrs_configuration = pcrs_configuration
        self.pcrs_idset_queue = pcrs_idset_queue
        self._pcrs_policy_ids = set()
        self.HOST = pcrs_configuration.host
        self.INDEX = pcrs_configuration.index
        self.EVENT_WRITER = event_writer
        self.pcrs_num_count_for_pid=pcrs_configuration.pcrs_num_count_for_pid
        self.custom_policy_ids = pcrs_configuration.custom_policy_ids
        self.retrycount=0
        self.pcrs_max_api_retry_count=pcrs_configuration.pcrs_max_api_retry_count
        self.pcrs_custom_policy_operation = pcrs_configuration.pcrs_custom_policy_operation

    @property
    def api_end_point(self):
        try:
            query_params={"lastEvaluationDate": self.pcrs_configuration.checkpoint_datetime}
            qlogger.debug(query_params)
            endpoint=self.BASE_ENDPOINT + "?" + str(urlpars.urlencode(query_params))
            return endpoint
        except:
            False
    
    def _parse(self, response_str):
        parseresponse = False
        rawJson = json.loads(response_str)   
          
        try:            
            data=rawJson['policyList']
            if self.custom_policy_ids == "":
                for value in data:
                    policy_id=value['id']
                    self._pcrs_policy_ids.add(str(policy_id))
                    event=Event(host=self.HOST,index=self.INDEX,source=self.SOURCE,sourcetype=self.SOURCETYPE)
                    event.data=json.dumps(value)
                    self.EVENT_WRITER.write_event(event)
            
            else :
                custom_policy_ids_list = list(map(str.strip, self.custom_policy_ids.split(',')))
                if self.pcrs_custom_policy_operation == "exclude":
                    for value in data:
                        policy_id=value['id']
                        if str(policy_id) not in custom_policy_ids_list :
                            self._pcrs_policy_ids.add(str(policy_id))

                            event=Event(host=self.HOST,index=self.INDEX,source=self.SOURCE,sourcetype=self.SOURCETYPE)
                            event.data=json.dumps(value)
                            self.EVENT_WRITER.write_event(event)

                elif self.pcrs_custom_policy_operation == "include":
                    for policyid in custom_policy_ids_list:
                        self._pcrs_policy_ids.add(str(policyid))
                        for value in data :
                            if value['id'] == int(policyid):

                                event=Event(host=self.HOST,index=self.INDEX,source=self.SOURCE,sourcetype=self.SOURCETYPE)
                                event.data=json.dumps(value)
                                self.EVENT_WRITER.write_event(event)

            qlogger.info("Number of Policy Ids parsed %s. Policy Ids received from Policy List API are %s",len(self._pcrs_policy_ids),self._pcrs_policy_ids)
            
        except Exception as e:
            self.retrycount +=1
            qlogger.error("An exception occurred while processing Policy List API for endpoint %s. Message: %s :: %s", self.api_end_point, str(e),traceback.format_exc())
            qlogger.error("An error occurred while parsing JSON API Output for Policy List API. JSON API Output received is: %s",response_str)
            return True
        self._post_parse()
        return parseresponse

    def _process_json_file(self, response):
        pass

    def _post_parse(self):
        #here each number is being added with comma as single digits-check 
        qlogger.info("Adding policy ids into pcrs_idset_queue")
        pcrsPolicyIdsList = list(self._pcrs_policy_ids)
        numPolicyIds = len(pcrsPolicyIdsList)

        numChunks = numPolicyIds / self.pcrs_num_count_for_pid

        if numPolicyIds % self.pcrs_num_count_for_pid != 0:
            numChunks += 1
        
        idChunks = qualysModule.splunkpopulator.utils.chunks(pcrsPolicyIdsList, math.floor(numChunks))
        idChunksList = list(idChunks)
        finalIdChunksList = list(filter(None, idChunksList))
        for idChunk in finalIdChunksList:
            idChunk=str(idChunk)
            self.pcrs_idset_queue.put(idChunk)
        self._pcrs_policy_ids = set()

class ThreadedResolveHostIDsPopulator(PCRSBasePopulatorJson):
    OBJECT_TYPE="Policy Compliance Reporting Service"
    ids= None
    BASE_ENDPOINT="/pcrs/1.0/posture/hostids"
    
    def __init__(self, ids, pcrsConfiguration):
        super(ThreadedResolveHostIDsPopulator, self).__init__(pcrsConfiguration.logger)
        self.pcrsConfiguration = pcrsConfiguration
        self.ids=ids
        self.host_ids_list=[]
        self.retrycount=0
        self.pcrs_max_api_retry_count=pcrsConfiguration.pcrs_max_api_retry_count
    
    @property
    def api_end_point(self):
        try:
            if self.pcrsConfiguration.last_scan_date_resolveHostId:
                query_params={"lastScanDate": self.pcrsConfiguration.checkpoint_datetime,"policyId": str(self.ids)}
            else:
                query_params={"policyId": str(self.ids)}
            qlogger.debug(query_params)
            endpoint=self.BASE_ENDPOINT + "?" + str(urlpars.urlencode(query_params))
            return endpoint
        except:
            False

    def _parse(self, response_str):
        parseresponse = False

        try:
            
            version=sys.version_info[0]
            if version<3:
                response_string=response_str.encode('utf-8')
                response_string=response_string.replace(r"u\"",'"')
                rawJson =json.loads(response_string)
            else:
                rawJson = json.loads(response_str)

            self.host_ids_list=rawJson
            for hosts in rawJson:
                qlogger.debug("Number of host Ids received from this api call %s for policy Id %s",len(hosts['hostIds']),hosts['policyId'])

        except Exception as e:
            self.retrycount +=1
            qlogger.error("An exception occurred while processing Resolve Host Ids API for endpoint %s. Message: %s :: %s", self.api_end_point, str(e),traceback.format_exc())
            qlogger.error("An error occurred while parsing JSON API Output for Resolve Host Ids API. JSON API Output received is: %s",response_str)
            return True
        return parseresponse

    def _process_json_file(self, response_str):
        pass

class ThreadedPostureInfoPopulator(PCRSBasePopulatorJson):
    OBJECT_TYPE="Policy Compliance Reporting Service (Posture Information)"
    SOURCE = 'qualys'
    SOURCETYPE = "qualys:pcrs:postureInfo"
    SUMMARY_SOURCETYPE= "qualys:pcrs:policy_summary"
    HOST = 'localhost'
    INDEX = 'main'
    ids= None
    LOGGED=0
    BASE_ENDPOINT="/pcrs/1.0/posture/postureInfo"

    def __init__(self, host_ids, event_writer, pcrsConfiguration):

        super(ThreadedPostureInfoPopulator, self).__init__(pcrsConfiguration.logger)
        self.pcrs_configuration=pcrsConfiguration
        self.ids=host_ids
        self.LOGGED=0
        self.HOST=pcrsConfiguration.host
        self.INDEX=pcrsConfiguration.index
        self.EVENT_WRITER=event_writer
        self.compressionRequired=1
        self.evidenceRequired=self.pcrs_configuration.evidenceRequired
        self.evidenceTruncationLimit=self.pcrs_configuration.evidenceTruncationLimit
        self.summary_controls=[]
        self.summary_passed=[]
        self.summary_failed=[]
        self.pcrs_max_api_retry_count = self.pcrs_configuration.pcrs_max_api_retry_count
        self.retrycount=0
        self.retry_429= False

    @property
    def api_end_point(self): 
        try:
            if self.evidenceRequired:
                self.evidenceRequired=1
            else:
                self.evidenceRequired=0    
                
            if self.evidenceTruncationLimit == 0:
                query_params={"evidenceRequired": str(self.evidenceRequired), "compressionRequired": str(self.compressionRequired)}
            else:
                query_params={"evidenceRequired": str(self.evidenceRequired), "compressionRequired": str(self.compressionRequired), "evidenceTruncationLimit": str(self.evidenceTruncationLimit)}
            
            if self.pcrs_configuration.last_scan_date_postureAPI:
                query_params.update({"lastScanDate":self.pcrs_configuration.checkpoint_datetime})
                
            qlogger.debug(query_params)
            endpoint=self.BASE_ENDPOINT + "?" + urlpars.urlencode(query_params)
            return endpoint
        except:
            False
    
    @property
    def get_api_parameters(self):
        version=sys.version_info[0]
        if version<3:
            ids_str=str(self.ids).encode('utf-8')
            param_host=ids_str.replace("'",'"')
            param_host_ids=param_host.replace('u"','"')
        else:
            param_host_ids=str(self.ids).replace("'",'"')
        return param_host_ids
    
    @property
    def get_logged_controls_count(self):
        return self.LOGGED

    def _fetch(self):
        api_params= self.get_api_parameters
        api_end_point = self.api_end_point
        
        if api_end_point:
            params = api_params
            try:
                retry_interval = int(self.api_client._config.retry_interval) if self.api_client._config.retry_interval else 300                    
                req=self.api_client._buildRequest(api_end_point, params, False, False)
                qlogger.info("Making request to Posture Info Streaming API: %s", req.get_full_url())
                timeout = int(self.api_client._config.api_timeout) if self.api_client._config.api_timeout else None
                method = req.get_method()
                ssl_verify = qualysModule.splunkpopulator.utils.bool_value(self.api_client._config.ssl_verify)
                qlogger.info("SSL Verification flag is set to : %s" % ssl_verify)
                qlogger.info("Timeout value is set to : %s seconds." % timeout)
                qlogger.info("Type of request: %s" % method)
                if self.api_client._config.useProxy:
                    try:
                        proxyDict={
                        'https' : self.api_client._config.proxyHost,
                        'http' : self.api_client._config.proxyHost
                        }
                        response=requests.post(url=req.get_full_url(),headers=req.headers,data=params,stream=True, timeout=timeout, verify=ssl_verify,proxies=proxyDict)
                    except (urllib3.exceptions.ProxySchemeUnknown, AssertionError):
                        proxyDict={
                        'https' : "https://"+self.api_client._config.proxyHost,
                        'http' : "https://"+self.api_client._config.proxyHost
                        }
                        response=requests.post(url=req.get_full_url(),headers=req.headers,data=params,stream=True, timeout=timeout, verify=ssl_verify,proxies=proxyDict)
                        
                else:
                    response=requests.post(url=req.get_full_url(),headers=req.headers,data=params,stream=True, timeout=timeout,verify=ssl_verify)
                if response.status_code==200:
                    self.retry_429=False

                if response.status_code!=200:
                    qlogger.debug("Got NOK response from API")
                    qlogger.debug("Response code from API: %s",response.status_code)
                    response.raise_for_status()
                    if response.status_code == 204:
                        qlogger.warning("No Content. Please check the request.")
                        try:
                            response.close()
                        except NameError:
                            pass
                        return response
                else:
                    return response
            except requests.exceptions.HTTPError as err:
                self.retrycount += 1
                if response.status_code==401:
                    
                    try:
                        qlogger.warn("JWTClient-001: JWT Token is expired, getting new token.")
                    except ValueError as e:
                        qlogger.warn("JWTClient-002: "+str(e)+". Unexpected response, refreshing the JWT token.")
                    except Exception as e:
                        qlogger.warn("JWTClient-003: "+str(e)+". Unexpected response, refreshing the JWT token.")
                    finally:
                        self.api_client.refreshToken()
                    qlogger.info("Retry Count: %s", self.retrycount-1)
                    try:
                        response.close()
                    except NameError:
                        pass
				# endif
                elif response.status_code==429:
                    self.retry_429= True
                    qlogger.error("Unsuccessful while calling API. Retrying after %s seconds. Error %s. Retry count: %s",retry_interval,err, self.retrycount-1)
                    time.sleep(retry_interval)     
                else:
                    qlogger.error("Unsuccessful while calling API. Retrying after %s seconds. Error %s. Retry count: %s",retry_interval,err, self.retrycount-1)
                    time.sleep(retry_interval)                    
            except requests.exceptions.ConnectionError as err:
                # Adding this for debugging purpose. Once the issue is fixed will remove exception logging from here.
                qlogger.info("Exception occurred while executing Posture Info Streaming API. Cause : %s" % err)
                if requests.exceptions.Timeout:
                    self.retrycount += 1
                    qlogger.error("Connection Timed out to %s . Sleeping for %s seconds and retrying. Retry count: %s",
							    req.get_full_url(), retry_interval, self.retrycount-1)
                    time.sleep(retry_interval)
                else:
                    self.retrycount += 1
                    qlogger.error("Error in connection: %s . Sleeping for %s seconds and retrying. Retry count: %s",err, retry_interval, self.retrycount-1)
                    time.sleep(retry_interval)
            except requests.exceptions.RequestException as err:
                self.retrycount += 1
                qlogger.error("Error during request to %s, Error: %s. Retry count: %s", api_end_point,err, self.retrycount-1)
                time.sleep(retry_interval)
            
        else:
            qlogger.error("Error during request to %s, Error: %s. Retry count: %s", api_end_point,err, self.retrycount-1)

    def run(self):
        response = self.__fetch_and_parse()
        return response        

    @property
    def get_retry_count(self):
        return self.retrycount

    def __fetch_and_parse(self):
        while (self.retrycount <= self.pcrs_max_api_retry_count) or (self.pcrs_max_api_retry_count==0) or self.retry_429== True:
            try:
                retry_interval = int(self.api_client._config.retry_interval) if self.api_client._config.retry_interval else 300   
                response = self._fetch()
                if response !=None :
                    if response.status_code == 204:
                        qlogger.warning("No contents matching given request.")
                        break 
                    else:
                        qlogger.debug("Response code from API: %s",response.status_code)

                    if response.status_code != 200:
                        qlogger.error("Error during Fetching, Cleaning up and retrying")
                        try:
                            time.sleep(3)
                            continue
                        except OSError:
                            pass

                    qlogger.info("%s fetched", self.OBJECT_TYPE)
                    parseresponse = self._parse(response)

                    if parseresponse:
                        qlogger.error("An error while fetching and parsing the API response. Retry count %s.",self.retrycount-1)
                        continue
                    else:
                        break
                
            except Exception as e:
                self.retrycount += 1
                import traceback
                if 'operation timed out' in six.text_type(e):
                    qlogger.error("Timeout while fetching, Retrying %s", e)
                else:
                    import traceback
                    qlogger.error("Exception while fetching or parsing. %s :: %s", str(e), traceback.format_exc())
                continue
        # endwhile
        if self.retrycount >= self.pcrs_max_api_retry_count and self.pcrs_max_api_retry_count != 0:
            qlogger.info("Maximum retry limit %s has reached.So skipping the following Policy Id %s with Host Ids %s for endpoint %s ",self.pcrs_max_api_retry_count, self.ids[0]['policyId'], self.ids[0]['hostIds'],self.api_end_point)

        return response        

    def trim_json(self, complete_json_string):
        if (complete_json_string.startswith("\"id\"")):
            complete_json_string="{"+complete_json_string
        if(complete_json_string.startswith("[{\"id")):
            complete_json_string=complete_json_string[1:]
        if(complete_json_string.startswith(",{\"id")):
            complete_json_string=complete_json_string[1:]
        if(complete_json_string.endswith("},{")):
            complete_json_string=complete_json_string[:-2]
        if(complete_json_string.endswith("]")):
            complete_json_string=complete_json_string[:-1]
        if not complete_json_string.endswith("}"):
            complete_json_string=complete_json_string+"}"
        if(complete_json_string.startswith("[{\"id")):
            complete_json_string=complete_json_string[1:]
        if(complete_json_string.endswith("]")):
            complete_json_string=complete_json_string[:-1]
        return complete_json_string

    def _parse(self, response):
        parseresponse = False
        decompress_chunk=zlib.decompressobj(16+zlib.MAX_WBITS)
        complete_json_string=''
        decoded_chunk=''
        exceptionOccured = False
        try:
            for chunk in response.iter_content(chunk_size=None):
                if exceptionOccured:
                    outstr += decompress_chunk.decompress(chunk)
                else:    
                    outstr = decompress_chunk.decompress(chunk) 
                try:
                    decoded_chunk = outstr.decode()
                    exceptionOccured = False
                except Exception as e:
                    if "'utf-8' codec can't decode byte" in str(e):
                        qlogger.warning(str(e))
                        exceptionOccured = True
                        continue
                    else:
                        qlogger.error("An exception occurred while processing Posture Info API for endpoint %s. Message: %s. Error: %s.", self.api_end_point, str(e),type(e))

                complete_json=re.split(r"(},{)",decoded_chunk)
                index=0

                while index<len(complete_json):
                    if(complete_json[index]!="},{"):
                        complete_json_string+=complete_json[index]
                        try:
                            #scenarios where list is not split at },{ because chunk has data as ,{}, or {},
                            if(complete_json_string!="[]"):
                                if(complete_json_string.endswith("},")):
                                    #when element ends at },
                                    if(complete_json_string.startswith("[")):
                                        #Element is [{},
                                        json.loads(complete_json_string[1:-1])
                                        complete_json_string=self.trim_json(complete_json_string[1:-1])
                                        self._process_json_file(complete_json_string)
                                        complete_json_string=""
                                    if not complete_json_string.startswith("{"):
                                        #when element is ...},
                                        json.loads("{"+complete_json_string[:-1])
                                        complete_json_string=self.trim_json("{"+complete_json_string[:-1])
                                        self._process_json_file(complete_json_string)
                                        complete_json_string=""
                                    else:
                                        json.loads(complete_json_string[:-1])
                                        complete_json_string=self.trim_json(complete_json_string[:-1])
                                        self._process_json_file(complete_json_string)
                                        complete_json_string=""

                                if(complete_json_string.startswith('"')and complete_json_string.endswith('"')):
                                    #element such as "id"
                                    json.loads("{"+complete_json_string+"}")

                                if(complete_json_string.startswith(",{")): 
                                    #when element starts at ,{
                                    if(complete_json_string.endswith("},")):
                                        #element is ,{},
                                        json.loads(complete_json_string[1:-1]) 
                                        complete_json_string=self.trim_json(complete_json_string[1:-1])
                                        self._process_json_file(complete_json_string)
                                        complete_json_string=""
                                    if(complete_json_string.endswith("]")):       
                                        #element is ,{}]                  
                                        json.loads(complete_json_string[1:-1])
                                        complete_json_string=self.trim_json(complete_json_string[1:-1])                                       
                                        self._process_json_file(complete_json_string)
                                        complete_json_string=""
                                    if not complete_json_string.endswith("}"):
                                        #element is ,{..
                                        json.loads(complete_json_string[1:]+"}")
                                        complete_json_string=self.trim_json(complete_json_string[1:]+"}")                                 
                                        self._process_json_file(complete_json_string)
                                        complete_json_string=""
                                    else:                                         
                                        json.loads(complete_json_string[1:]) 
                                        complete_json_string=self.trim_json(complete_json_string[1:])                                       
                                        self._process_json_file(complete_json_string)
                                        complete_json_string=""    

                                if(complete_json_string.endswith("}]")):
                                    #element is {}]
                                    complete_json_string=self.trim_json(complete_json_string[:-1])
                                    json.loads(complete_json_string)
                                    self._process_json_file(complete_json_string)
                                    complete_json_string=""    

                                if(complete_json_string.startswith("[{") and complete_json_string.endswith("}")):
                                    #element is [{}
                                    json.loads(complete_json_string[1:])
                                    complete_json_string=self.trim_json(complete_json_string[1:])
                                    self._process_json_file(complete_json_string)
                                    complete_json_string="" 

                                if not complete_json_string.startswith("{") and complete_json_string.endswith("}"):
                                    #element is ..}
                                    json.loads("{"+complete_json_string)
                                    complete_json_string=self.trim_json(complete_json_string)
                                    self._process_json_file(complete_json_string)
                                    complete_json_string=""

                                else:
                                    json.loads(complete_json_string)
                                    complete_json_string=self.trim_json(complete_json_string)
                                    self._process_json_file(complete_json_string)
                                    complete_json_string=""
                            else:
                                #clear str if str is []
                                complete_json_string=""
                                pass
                        except:
                            pass
                    else:
                        complete_json_string=self.trim_json(complete_json_string)
                        if complete_json_string=="}":
                            #clear str if str is trimmed },{
                            complete_json_string=""
                        try:
                            json.loads(complete_json_string)
                            self._process_json_file(complete_json_string)
                            complete_json_string=""
                        except:
                            pass
                    index+=1

            #eventtype- policy_summary
            summary_controls_logged={}
            
            for control in self.summary_controls:
                if (control in summary_controls_logged):
                    summary_controls_logged[control]+=1
                else:
                    summary_controls_logged[control]=1

            summary_passed_count={}
            
            for passed in self.summary_passed:
                if (passed in summary_passed_count):
                    summary_passed_count[passed]+=1
                else:
                    summary_passed_count[passed]=1

            summary_failed_count={}
            
            for failed in self.summary_failed:
                if (failed in summary_failed_count):
                    summary_failed_count[failed]+=1
                else:
                    summary_failed_count[failed]=1

            policy_summary={}
            for key,value in summary_controls_logged.items():
                policy_summary['POLICY_ID']=key
                policy_summary['NUMBER_OF_CONTROLS']=value
                if key in summary_passed_count.keys():
                    policy_summary['PASSED']=summary_passed_count[key]
                else:
                    policy_summary['PASSED']=0
                if key in summary_failed_count.keys():
                    policy_summary['FAILED']=summary_failed_count[key]
                else:
                    policy_summary['FAILED']=0
                
                event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SUMMARY_SOURCETYPE)
                event.data =json.dumps(policy_summary)
                self.EVENT_WRITER.write_event(event)

        except Exception as e:
            self.retrycount +=1
            qlogger.error("An exception occurred while processing Posture Info Streaming API for endpoint %s. Message: %s :: %s. Retry Count is %s", self.api_end_point, str(e),traceback.format_exc(),self.retrycount-1)
            qlogger.error("An error occurred while processing chunk received from Posture Info Streaming API. Chunk received is: %s",decoded_chunk)
            return True 
        return parseresponse

    def _process_json_file(self, complete_json):
        response_str=str(complete_json)

        try:
            rawJson=json.loads(response_str)
            qlogger.debug("Parsing started for CONTROL_ID=%s and HOST_ID=%s associated with POLICY_ID=%s.",str(rawJson['controlId']),str(rawJson['hostId']),str(rawJson['policyId']))
            self.LOGGED += 1
            event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SOURCETYPE)
            event.data = json.dumps(rawJson)
            self.EVENT_WRITER.write_event(event)
            self.summary_controls.append(str(rawJson['policyId']))
            if rawJson['status']=='Passed':
                self.summary_passed.append(str(rawJson['policyId']))
            else:                    
                self.summary_failed.append(str(rawJson['policyId']))

            qlogger.debug("Parsing completed for CONTROL_ID=%s and HOST_ID=%s associated with POLICY_ID=%s", str(rawJson['controlId']),str(rawJson['hostId']),str(rawJson['policyId']))
                       
            response_str=''
            return True
        
        except Exception as e:
            qlogger.error("Could not get posture info from API. Reason: %s :: %s ",str(e),traceback.format_exc())
            qlogger.error("Could not get posture info from Posture Info Streaming API. Posture received is: %s",response_str)
            self.save_chunk_file(str(response_str),'Chunk')
            return False
#end of ThreadedPostureInfoPopulator

    def save_chunk_file(self, Chunk,FILE_PREFIX):
        filename = temp_directory + "/%s_%s_%s_%s_.json.errored" % (FILE_PREFIX, datetime.now().strftime("%Y-%m-%d %H-%M-%S.%f"), current_thread().getName(), os.getpid())
        with open(filename,'w') as f:
            qlogger.debug("Saving Chunk file %s",filename)
            f.write(Chunk)