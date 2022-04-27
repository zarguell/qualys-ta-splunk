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
from qualysModule.splunkpopulator.utils import convertTimeFormat

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
from requests.exceptions import Timeout

import re
from requests.auth import HTTPProxyAuth

class PCRSPolicyPopulatorConfiguration(object):
    def __init__(self,logger):
        self.logger= logger

class PCRSPosturePopulatorConfiguration(PCRSPolicyPopulatorConfiguration):
    def __init__(self,logger):
        self.logger= logger
        self.evidenceRequired = False
        self.pcrs_posture_api_parameters = {}

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
        while True:
            try:
                response = self._fetch()

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
                    qlogger.error("An error while fetching and parsing the API response. Retrying.")
                    continue
                else:
                    break

            except Exception as e:
                import traceback
                qlogger.debug("Exception while parsing. %s :: %s", str(e), traceback.format_exc())
                if 'operation timed out' in six.text_type(e):
                    qlogger.error("Timeout while fetching, Retrying %s", e)
                else:
                    import traceback
                    qlogger.error("Exception while parsing. %s :: %s", str(e), traceback.format_exc())
                    raise BasePopulatorJsonException("could not load API response. Reason: %s" % str(e))
        # endwhile
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
    
            for value in data:
                policy_id=value['id']
                self._pcrs_policy_ids.add(str(policy_id))

                event=Event(host=self.HOST,index=self.INDEX,source=self.SOURCE,sourcetype=self.SOURCETYPE)
                event.data=json.dumps(value)
                self.EVENT_WRITER.write_event(event)
                
            qlogger.info("Number of Policy Ids parsed %s",len(self._pcrs_policy_ids))
            
        except Exception as e:
            qlogger.error("Failed to parse JSON API Output for endpoint %s. Message: %s", self.api_end_point, str(e))
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
    
    @property
    def api_end_point(self):
        try:
            query_params={"policyId": str(self.ids)}
            qlogger.debug(query_params)
            endpoint=self.BASE_ENDPOINT + "?" + str(urlpars.urlencode(query_params))
            return endpoint
        except:
            False

    def _parse(self, response_str):
        parseresponse = False

        version=sys.version_info[0]
        if version<3:
            response_string=response_str.encode('utf-8')
            response_string=response_string.replace(r"u\"",'"')
            res=json.dumps(response_string)
            rawJson = json.loads(res)
        else:
            rawJson = json.loads(response_str)

        try:
            self.host_ids_list=rawJson
            qlogger.info("Number of host Ids received from this api call %s",len(self.host_ids_list))
                                
        except Exception as e:
            qlogger.error("Failed to parse JSON API Output for endpoint %s. Message: %s", self.api_end_point, str(e))
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
        self.summary_controls=[]
        self.summary_passed=[]
        self.summary_failed=[]

    @property
    def api_end_point(self): 
        try:
            if self.evidenceRequired:
                self.evidenceRequired=1
            else:
                self.evidenceRequired=0
            
            query_params={"evidenceRequired": str(self.evidenceRequired), "compressionRequired": str(self.compressionRequired)}
            qlogger.debug(query_params)
            endpoint=self.BASE_ENDPOINT + "?" + urlpars.urlencode(query_params)
            return endpoint
        except:
            False
    
    @property
    def get_api_parameters(self):
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
            while True:
                try:
                    retry_interval = int(self.api_client._config.retry_interval) if self.api_client._config.retry_interval else 300
                    retrycount = 0
                    req=self.api_client._buildRequest(api_end_point, params, False, False)

                    qlogger.info("Making request to Posture Info Streaming API: %s", req.get_full_url())
                    timeout = int(self.api_client._config.api_timeout) if self.api_client._config.api_timeout else None
                    method = req.get_method()
                    qlogger.info("Type of request: %s" % method)

                    if self.api_client._config.useProxy:
                        proxyDict={
                        'https' : self.api_client._config.proxyHost
                        }
                        response=requests.post(url=req.get_full_url(),headers=req.headers,data=params,stream=True, timeout=timeout, verify=False, proxies=proxyDict)
                    else:
                        response=requests.post(url=req.get_full_url(),headers=req.headers,data=params,stream=True, timeout=timeout, verify=False)

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
                    retrycount += 1
                    if response.status_code==401:
                        try:
                            qlogger.info("JWTClient-001: JWT Token is expired, getting new token.")
                            self.api_client.refreshToken()
                        except ValueError as e:
                            qlogger.debug("JWTClient-002: "+str(e)+". Unexpected response, refreshing the JWT token.")
                        except Exception as e:
                            qlogger.debug("JWTClient-003: "+str(e)+". Unexpected response, refreshing the JWT token.")
                        finally:
                            self.api_client.refreshToken()
                        qlogger.exception("Retry Count: %s", retrycount)
                        try:
                            response.close()
                        except NameError:
                            pass
                        continue
					# endif
                    else:
                        qlogger.error("Unsuccessful while calling API. Retrying after %s seconds. Error %s. Retry count: %s",retry_interval,err, retrycount)
                        time.sleep(retry_interval)                    
                except requests.exceptions.ConnectionError as err:
                    if requests.exceptions.Timeout:
                        retrycount += 1
                        qlogger.error("Connection Timed out to %s . Sleeping for %s seconds and retrying. Retry count: %s",
								    req.get_full_url(), retry_interval, retrycount)
                        time.sleep(retry_interval)
                    else:
                        retrycount += 1
                        qlogger.error("Error in connection: %s . Sleeping for %s seconds and retrying. Retry count: %s",err, retry_interval, retrycount)
                        time.sleep(retry_interval)
                except requests.exceptions.RequestException as err:
                    qlogger.error("Error during request to %s, Error: %s", api_end_point,err)
                    break
            
        else:
            raise Exception("API endpoint not set, when fetching values for Object type:%", self.OBJECT_TYPE)

    def run(self):
        response = self.__fetch_and_parse()
        return response        

    def __fetch_and_parse(self):
        while True:
            try:
                response = self._fetch()

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
                    qlogger.error("An error while fetching and parsing the API response. Retrying.")
                    continue
                else:
                    break
                
            except Exception as e:
                import traceback
                qlogger.debug("Exception while parsing. %s :: %s", str(e), traceback.format_exc())
                if 'operation timed out' in six.text_type(e):
                    qlogger.error("Timeout while fetching, Retrying %s", e)
                else:
                    import traceback
                    qlogger.error("Exception while parsing. %s :: %s", str(e), traceback.format_exc())
                    raise BasePopulatorJsonException("could not load API response. Reason: %s" % str(e))
        # endwhile
        return response        

    def _parse(self, response):
        parseresponse = False
        chunk_res=''
        decompress_chunk=zlib.decompressobj(16+zlib.MAX_WBITS)
        complete_json_string=''
        form_complete_json=[]

        try:
            for chunk in response.iter_content(chunk_size=1048576):
                decompress_res=decompress_chunk.decompress(chunk)
                chunk_res=decompress_res

                complete_json=re.split(r"(},{)",chunk_res.decode())
                index=0
                if len(complete_json)==1:
                    if complete_json[index].startswith("[{\"id") and complete_json[index].endswith("}]") or (complete_json[index].startswith("{\"id\"") and complete_json[index].endswith("]}}")):
                        self._process_json_file(complete_json[index])
                    else:
                        if complete_json[index]=='[]':
                            pass
                        else:
                            form_complete_json.append(complete_json[index])
                            for val in form_complete_json:
                                complete_json_string+=val
                            if (complete_json_string.startswith("\"id\"") and complete_json_string.endswith("},{")) or (complete_json_string.startswith("[{\"id") and complete_json_string.endswith("},{")) or (complete_json[index].startswith("[{\"id") and complete_json[index].endswith("}]")) or (complete_json[index].startswith("\"id\"") and complete_json[index].endswith("}]")) or (complete_json[index].startswith("\"id\"") and complete_json[index].endswith("]}}")) or (complete_json[index].startswith("{\"id\"") and complete_json[index].endswith("]}}")):
                                self._process_json_file(complete_json_string)
                                form_complete_json=[]
                                complete_json_string=''
                            else:
                                complete_json_string=''

                while index<len(complete_json)-1:
                    if complete_json[index]=="},{":
                        pass
                    else:
                        if complete_json[index+1]=="},{":
                            complete_json[index]+=complete_json[index+1]
                        else:
                            pass
                
                    if (complete_json[index].startswith("\"id\"") and complete_json[index].endswith("},{")) or (complete_json[index].startswith("[{\"id") and complete_json[index].endswith("},{")) or (complete_json[index].startswith("[{\"id") and complete_json[index].endswith("}]")) or (complete_json[index].startswith("\"id\"") and complete_json[index].endswith("]}}")) or (complete_json[index].startswith("{\"id\"") and complete_json[index].endswith("]}}")):
                        self._process_json_file(complete_json[index])
                    else:
                        if complete_json[index]=="},{":
                            pass
                        else:
                            form_complete_json.append(complete_json[index])
                            for val in form_complete_json:
                                complete_json_string+=val
                            if (complete_json_string.startswith("\"id\"") and complete_json_string.endswith("},{")) or (complete_json_string.startswith("[{\"id") and complete_json_string.endswith("},{")) or (complete_json[index].startswith("[{\"id") and complete_json[index].endswith("}]")) or (complete_json[index].startswith("\"id\"") and complete_json[index].endswith("}]")) or (complete_json[index].startswith("\"id\"") and complete_json[index].endswith("]}}")) or (complete_json[index].startswith("{\"id\"") and complete_json[index].endswith("]}}")):
                                self._process_json_file(complete_json_string)
                                form_complete_json=[]
                                complete_json_string=''
                            else:
                                complete_json_string=''

                    if index==len(complete_json)-2:
                        if (complete_json[index+1].startswith("\"id\"") and complete_json[index+1].endswith("}]")) or (complete_json[index+1].startswith("[{\"id") and complete_json[index+1].endswith("},{")) or (complete_json[index].startswith("[{\"id") and complete_json[index].endswith("}]")) or (complete_json[index].startswith("\"id\"") and complete_json[index].endswith("]}}")) or (complete_json[index].startswith("{\"id\"") and complete_json[index].endswith("]}}")):
                            self._process_json_file(complete_json[index+1])
                        else:
                            form_complete_json.append(complete_json[index+1])
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
            qlogger.error("Failed to parse JSON API Output for endpoint %s. Message: %s", self.api_end_point, str(e))
            return True 
        return parseresponse

    def _process_json_file(self, complete_json):
        response_str=str(complete_json)

        try:
            if (response_str.startswith("\"id\"")):
                response_str="{"+response_str
            if(response_str.startswith("[{\"id")):
                response_str=response_str[1:]
            if(response_str.endswith("},{")):
                response_str=response_str[:-2]
            if(response_str.endswith("]")):
                response_str=response_str[:-1]
            
            if ("}\"id\"" in response_str):
                split_json=response_str.split("}\"id\"")
                
                for val in split_json:
                    if val.startswith(":"):
                        val="{\"id\"" + val
                    if val.endswith("]}"):
                        val+="}}"
                    rawJson=json.loads(val)
                    self.LOGGED += 1
                    event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SOURCETYPE)
                    event.data = json.dumps(rawJson)
                    self.EVENT_WRITER.write_event(event)

                    self.summary_controls.append(str(rawJson['policyId']))
                    if rawJson['status']=='Passed':
                        self.summary_passed.append(str(rawJson['policyId']))
                    else:
                        self.summary_failed.append(str(rawJson['policyId']))
            else:
                rawJson=json.loads(response_str)
                self.LOGGED += 1
                event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SOURCETYPE)
                event.data = json.dumps(rawJson)
                self.EVENT_WRITER.write_event(event)

                self.summary_controls.append(str(rawJson['policyId']))
                if rawJson['status']=='Passed':
                    self.summary_passed.append(str(rawJson['policyId']))
                else:
                    self.summary_failed.append(str(rawJson['policyId']))
            
            qlogger.debug("POLICY_ID=%s Parsing Started.",str(rawJson['policyId']))
            qlogger.debug("POLICY_ID=%s Parsing Completed.", str(rawJson['policyId']))
            
            response_str=''
            return True
        
        except Exception as e:
            qlogger.error("Could not get posture info from API. Reason: " + str(e))
            return False
#end of ThreadedPostureInfoPopulator