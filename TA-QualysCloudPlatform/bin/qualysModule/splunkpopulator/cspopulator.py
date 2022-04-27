__author__ = 'Qualys, Inc'
# -*- coding: utf-8 -*-
__copyright__ = "Copyright (C) 2018, Qualys, Inc"
__license__ = "New BSD"
__version__ = "1.0"

import os
import csv
import time
import json
import six.moves.urllib.request as urlreq, six.moves.urllib.parse as urlpars, six.moves.urllib.error as urlerr
from threading import current_thread

from qualysModule.splunkpopulator.basepopulator_json import BasePopulatorJson, BasePopulatorJsonException
from collections import namedtuple
from qualysModule import qlogger

from qualysModule.splunkpopulator.utils import convertTimeFormat
from threading import current_thread
from qualysModule.lib import api

from qualysModule import *
from lib.splunklib.modularinput import Event
from io import open

"""Container Secutiry Image Populator Configuration"""


class CsImagePopulatorConfiguration(object):
    _params_not_allowed = ["updated"]

    def __init__(self, logger):
        self.logger = logger
        self.cs_image_api_extra_parameters = ""
        self.updated = 'updated>='
        self.updatedDate = ""
        self.end_date = ""

    def add_cs_api_filter(self, extra_params, user_defined=False):
        try:
            qlogger.info("Adding CS Image API extra parameter -  %s", extra_params)
            self.cs_image_api_extra_parameters = extra_params
        except Exception as e:
            qlogger.warning("Exception: CS API filter - %s", str(e))


class CSContainerPopulatorConfiguration(object):
    _params_not_allowed = ["updated"]

    def __init__(self, logger):
        self.logger = logger
        self.extra_filters = ""
        self.page_number = 0
        self.page_size = 1000
        self.end_date = ""

    # TODO: Revisit this method and restructure
    def add_api_filter(self, name, value, operator, user_defined=False):
        name = name.replace("\"", "")
        if not user_defined or name not in self._params_not_allowed:
            qlogger.info("Adding Container API parameter: %s %s %s", name, operator, value)
            self.extra_filters.append("%s%s%s" % (name, operator, value))
        else:
            qlogger.warning("Parameter %s is not allowed in Container Populator. Not adding to API call.", name)

    def validate_extra_filters(self, user_defined_filters):
        for not_allowed_param in self._params_not_allowed:
            if not_allowed_param in user_defined_filters:
                return False, not_allowed_param
        return True, None


"""Container Secutiry Image Populator"""


class QualysCSImagePopulator(BasePopulatorJson):
    OBJECT_TYPE = "Container Security Image"
    FILE_PREFIX = "cs_image_list"
    SOURCE = 'qualys'
    SOURCETYPE = 'qualys:cs:csImageInfo'
    HOST = 'localhost'
    INDEX = 'main'
    ROOT_TAG = "data"
    FIRST_PAGE = True  # changes to False after first page (page 0) is processed

    def __init__(self, cs_configuration, cs_idset_queue, event_writer):
        super(QualysCSImagePopulator, self).__init__(cs_configuration.logger)
        self.cs_configuration = cs_configuration
        self.cs_idset_queue = cs_idset_queue
        self.LOGGED = 0
        self.HOST = cs_configuration.host
        self.INDEX = cs_configuration.index
        self.checkpointData = cs_configuration.checkpointData
        self.EVENT_WRITER = event_writer
        # self.page_numbers = [1]
        self.CURRENT_PAGE_NUMBER = 1
        self.last_updated_batch = self.cs_configuration.start_date
        self.batch = 1
        self.total_img_count = 0
        self.page_size = cs_configuration.cs_image_page_size
        self.filter = ""

    @property
    def get_logged_img_count(self):
        return self.LOGGED

    @property
    def get_total_img_count(self):
        return self.total_img_count

    @property
    def api_end_point(self):
        """
        we add API params in this method to allow GET request be made.
        """
        try:
            # qlogger.debug(self.page_numbers)
            # self.CURRENT_PAGE_NUMBER = self.page_numbers[0]
            qlogger.info("Trying to download page number %d", self.CURRENT_PAGE_NUMBER)
            filter = 'updated:["%s".."%s"]' % (self.last_updated_batch, self.cs_configuration.end_date)
            query_params = {"pageSize": str(self.page_size), "pageNumber": str(self.CURRENT_PAGE_NUMBER),
                            "filter": filter, "sort": "updated:asc"}
            if self.cs_configuration.cs_image_api_extra_parameters not in ("", None):
                query_params["filter"] = self.cs_configuration.cs_image_api_extra_parameters + " and (" + filter + ")"
            endpoint = "/csapi/v1.3/images?" + str(urlpars.urlencode(query_params))
            return endpoint
        except:
            return False

    '''
    def list_page_numbers(self, number_of_images):
        required_api_calls = int(number_of_images / self.page_size)
        rem = number_of_images % self.page_size
        if rem > 0:
            required_api_calls = required_api_calls + 1
        qlogger.info("TA need to make %d more API calls to get list of all images.", required_api_calls)
        #self.page_numbers.extend(list(range(2, required_api_calls+1)))
        qlogger.info("Page numbers list updated for get images list API call.")
    '''

    """
    This _parse method overriding will handle the pagination of the imageIds
    """

    def _parse(self, file_name):
        parseresponse = {'next_batch_url': True}
        qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Started', self.OBJECT_TYPE, file_name)
        self._pre_parse()

        try:
            self._process_json_file(file_name)
            '''if len(self.page_numbers) == 0:
                del parseresponse['next_batch_url']  # remove key to break the loop in run()
            '''
        except JSONDecodeError as e:
            qlogger.error("Failed to parse JSON API Output for endpoint %s. Message: %s", self.api_end_point, str(e))
            '''if len(self.page_numbers) >= 1 and self.CURRENT_PAGE_NUMBER != 0:
                qlogger.error("Could not parse page number %d. Proceeding with next page number.",
                              self.CURRENT_PAGE_NUMBER)
                self.page_numbers.pop(0)
                return {'next_batch_url': True}
            else:
                return {}
            '''
        self._post_parse()

        qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Completed', self.OBJECT_TYPE, file_name)
        return parseresponse

    def _process_json_file(self, file_name):
        rawJson = json.load(open(file_name))
        try:
            # Get the imageId data inside the 'data' array
            data = rawJson['data']
            # for count of records fetched
            count = len(data)
            # for count of records in the count key of the json
            self.total_img_count = rawJson['count']

            if self.FIRST_PAGE:
                qlogger.info("Total %d images to be processed in this run.", self.total_img_count)
                # self.list_page_numbers(self.total_img_count)
                self.FIRST_PAGE = False

            qlogger.info("Images in page %d = %d", self.CURRENT_PAGE_NUMBER, count)

            # to dump a json data event in splunk and to send the image sha and uniqueKey (registry|repository)
            last_batch = self.last_updated_batch
            for value in data:
                # to queue image sha and uniqueKey (registry|repository)
                imageSha = value["sha"]
                qlogger.info("image sha=%s Parsing Started.", imageSha)
                if value["repo"]:
                    registry = value["repo"][0]["registry"]
                    repository = value["repo"][0]["repository"]
                else:
                    registry = "Unknown"
                    repository = "Unknown"
                uniqueKey = str(registry) + "|" + str(repository)
                value["uniqueKey"] = uniqueKey
                value["type"] = "IMAGE_INFO"
                # convert the epoch dates to human readable format
                value["created"] = convertTimeFormat(value["created"])
                value["updated"] = convertTimeFormat(value["updated"])

                # Index the value in Splunk
                event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SOURCETYPE)
                event.data = json.dumps(value)
                self.EVENT_WRITER.write_event(event)
                self.LOGGED += 1
                qlogger.info("image sha=%s Parsing Completed.", imageSha)

                # append imageSha & uniqueKey in the list for cs_idset_queue
                imgId = ("{\'imageSha\':\'" + imageSha + "\',\'uniqueKey\':\'" + uniqueKey + "\'}")
                self.cs_idset_queue.put(imgId)
                qlogger.info("Pushing into queue: %s" % imgId)
                self.checkpointData['last_run_datetime'] = value["updated"]
                last_batch = value["updated"]

            if (self.page_size * (self.CURRENT_PAGE_NUMBER + 1) > 10000):
                self.batch += 1
                self.CURRENT_PAGE_NUMBER = 1
                self.last_updated_batch = self.cs_configuration.end_date
            else:
                self.CURRENT_PAGE_NUMBER += 1

            # self.page_numbers.pop(0)
            return True
        except Exception as e:
            qlogger.error("Could not process %s element. Error: %s", self.ROOT_TAG, str(e))
            return False


# End of QualysCSImagePopulator class

"""Container Secutiry Image Vulnarabilities Populator"""


class ThreadedCsVulnInfoPopulator(BasePopulatorJson):
    OBJECT_TYPE = "Container Security Image Vulnarabilities"
    FILE_PREFIX = "cs_image_vulns_list"
    ROOT_TAG = "vulnerabilities"
    IMAGE_LABEL_TAG = "label"
    SOURCE = 'qualys'
    SOURCETYPE = 'qualys:cs:csImageVulnInfo'
    HOST = 'localhost'
    INDEX = 'main'
    keyDict = None
    LOGGED = 0
    IMAGEID = ""

    def __init__(self, keyDict, event_writer, imgVulnsConfiguration):
        super(ThreadedCsVulnInfoPopulator, self).__init__(imgVulnsConfiguration.logger)
        self.cs_vulns_configuration = imgVulnsConfiguration
        self.keyDict = keyDict
        self.LOGGED = 0
        self.HOST = imgVulnsConfiguration.host
        self.INDEX = imgVulnsConfiguration.index
        self.EVENT_WRITER = event_writer
        self.image_sha = self.keyDict["imageSha"]
        self.uniqueKey = self.keyDict["uniqueKey"]

    # end of __init__

    @property
    def api_end_point(self):
        return "/csapi/v1.3/images/" + str(self.keyDict["imageSha"])

    @property
    def get_logged_vulns_count(self):
        return self.LOGGED

    def _fetch(self):
        api_params = {}
        api_end_point = self.api_end_point
        if api_end_point:
            filename = temp_directory + "/%s_%s_%s_%s_image_%s.json" % (
                self.FILE_PREFIX, start_time.strftime('%Y-%m-%d-%M-%S'), current_thread().getName(), os.getpid(),
                self.image_sha)
            response = self.api_client.get(api_end_point, api_params, api.Client.XMLFileBufferedResponse(filename))
            return response
        else:
            raise Exception("API endpoint not set, when fetching values for Object type:%", self.OBJECT_TYPE)

    def _parse(self, file_name):
        qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Started', self.OBJECT_TYPE, file_name)
        try:
            self._pre_parse()
            self._process_json_file(file_name)
            self._post_parse()
        except Exception as e:
            qlogger.error("Failed to parse JSON API Output for endpoint %s. Message: %s", self.api_end_point, str(e))
        finally:
            qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Completed', self.OBJECT_TYPE, file_name)
            return {}

    # End of _parse

    def _process_json_file(self, file_name):
        rawJson = json.load(open(file_name))
        strRawJson = json.dumps(rawJson)
        qlogger.info("image sha=%s. Parsing=Started", self.image_sha)
        try:
            if self.ROOT_TAG in strRawJson:
                # Get Vuln data
                vulnerabilityData = rawJson[self.ROOT_TAG]
                
                # Get Image Label data
                imageLabelData = rawJson[self.IMAGE_LABEL_TAG]
                
                # Get Image Id data
                imageIdData = rawJson["imageId"]
                
                # Get Vuln Summary
                vulnSummaryData = {"confirmed": {"sev1Count":0, "sev2Count":0, "sev3Count":0, "sev4Count":0, "sev5Count":0}, "potential": {"sev1Count":0, "sev2Count":0, "sev3Count":0, "sev4Count":0, "sev5Count":0}, "patchAvailability": {"confirmed": {"sev1Count":0, "sev2Count":0, "sev3Count":0, "sev4Count":0, "sev5Count":0}, "potential": {"sev1Count":0, "sev2Count":0, "sev3Count":0, "sev4Count":0, "sev5Count":0}}}
                
                # to dump a json data event in splunk
                if vulnerabilityData is not None:
                    for jsonKey in vulnerabilityData:
                        jsonKey["imageId"] = imageIdData
                        jsonKey["sha"] = self.image_sha
                        jsonKey["uniqueKey"] = self.uniqueKey
                        jsonKey["type"] = "VULN_INFO"

                        # convert the epoch dates to human readable format
                        jsonKey["firstFound"] = convertTimeFormat(jsonKey["firstFound"])
                        jsonKey["lastFound"] = convertTimeFormat(jsonKey["lastFound"])
                        jsonKey["label"] = imageLabelData

                        # Increase the count of severity by 1 based on typeDetected
                        vulnSummaryData[jsonKey["typeDetected"].lower()]["sev"+str(jsonKey["severity"])+"Count"] += 1
                        
                        # If patch is available, increase the count of severity by 1
                        if jsonKey["patchAvailable"]:
                            vulnSummaryData["patchAvailability"][jsonKey["typeDetected"].lower()]["sev"+str(jsonKey["severity"])+"Count"] += 1

                        # Index the jsonKey in Splunk
                        if self.cs_vulns_configuration.cs_log_individual_events:
                            event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE,
                                          sourcetype=self.SOURCETYPE)
                            event.data = json.dumps(jsonKey)
                            self.EVENT_WRITER.write_event(event)
                        self.LOGGED += 1

                # Add the imageId and uniqueKey in the vulnSummaryData
                vulnSummaryData["imageId"] = imageIdData
                vulnSummaryData["sha"] = self.image_sha
                vulnSummaryData["uniqueKey"] = self.uniqueKey
                vulnSummaryData["type"] = "VULN_SUMMARY"

                # Index the vulnSummaryData in Splunk
                if self.cs_vulns_configuration.cs_log_summary_events:
                    event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SOURCETYPE)
                    event.data = json.dumps(vulnSummaryData)
                    self.EVENT_WRITER.write_event(event)
                qlogger.info("image sha=%s. Parsing=Completed.", self.image_sha)
            return True
        except Exception as e:
            qlogger.error("Could not process %s element. Error: %s", self.ROOT_TAG, str(e))
            return False


# End of ThreadedCsVulnInfoPopulator class

"""Container Secutiry Container Vulnarabilities Populator"""


class ThreadedContainerVulnInfoPopulator(BasePopulatorJson):
    OBJECT_TYPE = "CS Container Vulnarabilities"
    FILE_PREFIX = "cs_container_vulns"
    ROOT_TAG = "details"
    VULN_SUMMERY = "vulnSummary"
    SOURCE = 'qualys'
    CONTAINER_SOURCETYPE = 'qualys:cs:container'
    VULN_SOURCETYPE = 'qualys:cs:containerVuln'
    HOST = 'localhost'
    INDEX = 'main'
    LOGGED_CONTAINERS_COUNT = 0
    LOGGED_VULNS_COUNT = 0
    CONTAINER_SHA = ""
    BASE_ENDPOINT = "/csapi/v1.3/containers/%s"
    UNWANTED_KEYS = ["softwares", "rogue"]
    CONTAINER_TIME_KEYS_TO_CONVERT = ["created", "stateChanged", "updated"]
    VULN_TIME_KEYS_TO_CONVERT = ["lastFound", "firstFound"]

    def __init__(self, container_sha, event_writer, cs_configuration):
        super(ThreadedContainerVulnInfoPopulator, self).__init__(cs_configuration.logger)
        self.CONTAINER_SHA = container_sha
        self.EVENT_WRITER = event_writer
        self.cs_configuration = cs_configuration
        self.HOST = cs_configuration.host
        self.INDEX = cs_configuration.index

    @property
    def api_end_point(self):
        return self.BASE_ENDPOINT % self.CONTAINER_SHA

    @property
    def get_logged_vulns_count(self):
        return self.LOGGED_VULNS_COUNT

    def _fetch(self):
        api_params = {}
        if self.api_end_point:
            api_params = self.get_api_parameters
            filename = temp_directory + "/%s_%s_%s_%s_container_%s.json" % (
                self.FILE_PREFIX, start_time.strftime('%Y-%m-%d-%M-%S'), current_thread().getName(),
                os.getpid(), self.CONTAINER_SHA)
            response = self.api_client.get(self.api_end_point, api_params, api.Client.XMLFileBufferedResponse(filename))
            return response
        else:
            qlogger.info("No endpoint set for %s", self.OBJECT_TYPE)

    def _parse(self, file_name):
        qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Started', self.OBJECT_TYPE, file_name)
        try:
            self._pre_parse()
            self._process_json_file(file_name)
            self._post_parse()
        except Exception as e:
            qlogger.error("Failed to parse JSON API Output for endpoint %s. Message: %s", self.api_end_point, str(e))
        finally:
            qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Completed', self.OBJECT_TYPE, file_name)
            return {}

    # End of _parse method

    def _process_json_file(self, file_name):
        responseJson = json.load(open(file_name))
        try:
            # remove unwanted JSON keys
            for unwanted_key in self.UNWANTED_KEYS:
                try:
                    del responseJson[unwanted_key]
                except:
                    pass

            # 'extract' vulnerabilities
            vulns = responseJson["vulnerabilities"]
            del responseJson["vulnerabilities"]

            # convert timings to human readable values
            for t in self.CONTAINER_TIME_KEYS_TO_CONVERT:
                responseJson[t] = convertTimeFormat(responseJson[t])

            # dump a container json data event in splunk
            responseJson["type"] = "CONTAINER_DETAILS"
            event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.CONTAINER_SOURCETYPE)
            event.data = json.dumps(responseJson)
            self.EVENT_WRITER.write_event(event)
            self.LOGGED_CONTAINERS_COUNT = self.LOGGED_CONTAINERS_COUNT + 1

            # now iterate over vulns
            summary = {
                "type": "CONTAINER_VULN_SUMMARY",
                "sha": self.CONTAINER_SHA,
                "container_id": responseJson["containerId"],
                "name": responseJson["name"],
                "image_id": responseJson["imageId"],
                "total_vulns": 0,
                "potential": 0,
                "potential_by_severity": {
                    "sev_5": 0,
                    "sev_4": 0,
                    "sev_3": 0,
                    "sev_2": 0,
                    "sev_1": 0
                },
                "confirmed": 0,
                "confirmed_by_severity": {
                    "sev_5": 0,
                    "sev_4": 0,
                    "sev_3": 0,
                    "sev_2": 0,
                    "sev_1": 0
                },
                "patchable_vulns": 0
            }

            if vulns is None:
                qlogger.debug("Container sha %s has no vulnerabilities reported.", self.CONTAINER_SHA)
            else:
                for vuln in vulns:
                    # convert timings to human readable format
                    for t in self.VULN_TIME_KEYS_TO_CONVERT:
                        vuln[t] = convertTimeFormat(vuln[t])

                    # gather some summary data
                    summary["total_vulns"] += 1
                    vuln_type_key = vuln["typeDetected"].lower()
                    summary[vuln_type_key] += 1
                    by_sev_key = "%s_by_severity" % vuln_type_key
                    sev_key = "sev_%d" % vuln["severity"]
                    summary[by_sev_key][sev_key] += 1
                    if vuln["patchAvailable"]:
                        summary["patchable_vulns"] += 1

                    # add container id and type to this JSON
                    vuln["containerId"] = responseJson["containerId"]
                    vuln["sha"] = self.CONTAINER_SHA
                    vuln["type"] = "CONTAINER_VULN"

                    if self.cs_configuration.cs_log_individual_events:
                        event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE,
                                      sourcetype=self.VULN_SOURCETYPE)
                        event.data = json.dumps(vuln)
                        self.EVENT_WRITER.write_event(event)
                        self.LOGGED_VULNS_COUNT = self.LOGGED_VULNS_COUNT + 1

            if self.cs_configuration.cs_log_summary_events:
                event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.VULN_SOURCETYPE)
                event.data = json.dumps(summary)
                self.EVENT_WRITER.write_event(event)
            # loop on vulns

            qlogger.info("Container sha %s Parsing Completed.", self.CONTAINER_SHA)
            return True
        except Exception as e:
            qlogger.error("Could not process %s element. Error: %s", self.OBJECT_TYPE, str(e))
            return False


# End of ThreadedContainerVulnInfoPopulator class

"""Container Secutiry Container Populator"""


class QualysContainerPopulator(BasePopulatorJson):
    OBJECT_TYPE = "Qualys CS Container"
    FILE_PREFIX = "cs_containers_list"
    SOURCE = 'qualys'
    SOURCETYPE = 'qualys:cs:containerInfo'
    HOST = 'localhost'
    INDEX = 'main'
    DATA_KEY = "data"
    BASE_ENDPOINT = "/csapi/v1.3/containers"
    FIRST_PAGE = True  # changes to False after first page (page 0) is processed

    def __init__(self, cs_configuration, cs_idset_queue, event_writer):
        super(QualysContainerPopulator, self).__init__(cs_configuration.logger)
        self.cs_configuration = cs_configuration
        self.cs_idset_queue = cs_idset_queue
        self.LOGGED_CONTAINERS_COUNT = 0
        self.TOTAL_CONTAINERS = 0
        self.NULL_CONTAINERS = 0
        self.HOST = cs_configuration.host
        self.INDEX = cs_configuration.index
        self.checkpointData = cs_configuration.checkpointData
        self.EVENT_WRITER = event_writer
        self.__file_name = ""
        # self.page_numbers = list(cs_configuration.page_number)
        # self.page_numbers = [1]
        self.page_size = cs_configuration.page_size
        self.filter = ""
        self.CONTAINER_SHA = ""
        self.CURRENT_PAGE_NUMBER = 1
        self.last_updated_batch = self.cs_configuration.start_date
        self.batch = 1

    @property
    def get_logged_containers_count(self):
        return self.LOGGED_CONTAINERS_COUNT

    @property
    def get_total_containers_count(self):
        return self.TOTAL_CONTAINERS

    @property
    def get_null_containers_count(self):
        return self.NULL_CONTAINERS

    @property
    def get_api_parameters(self):
        """
        we do not return API params from this method, because it causes POST request
        which is not supported for get containers/container vulns API call.
        """
        return {}

    def get_last_scanned_date_filter(self):
        return 'updated:["%s".."%s"]' % (self.last_updated_batch, self.cs_configuration.end_date)

    @property
    def api_end_point(self):
        """
        we add API params in this method to allow GET request be made.
        """
        try:
            # self.CURRENT_PAGE_NUMBER = self.page_numbers.pop(0)
            # qlogger.debug(self.page_numbers)
            # self.CURRENT_PAGE_NUMBER = self.page_numbers[0]
            qlogger.info("Trying to download batch %d, page number %d", self.batch, self.CURRENT_PAGE_NUMBER)
            query_params = {"pageSize": str(self.page_size), "pageNumber": str(self.CURRENT_PAGE_NUMBER),
                            "filter": self.get_last_scanned_date_filter(), "sort": "updated:asc"}

            if self.cs_configuration.extra_filters != "":
                query_params["filter"] = query_params["filter"] + " and (" + self.cs_configuration.extra_filters  + ")"
            qlogger.debug(query_params)

            endpoint = self.BASE_ENDPOINT + "?" + urlpars.urlencode(query_params)
            return endpoint
        except:
            return False

    '''def list_page_numbers(self, number_of_containers):
        required_api_calls = int(number_of_containers / self.page_size)
        rem = number_of_containers % self.page_size
        if rem > 0:
            required_api_calls = required_api_calls + 1
        qlogger.info("TA need to make %d more API calls to get list of all containers.", required_api_calls)
        self.page_numbers.extend(list(range(2, required_api_calls+1)))
        qlogger.info("Page numbers list updated for get container list API call.")
    '''

    def _fetch(self):
        api_params = {}
        if self.api_end_point:
            api_params = self.get_api_parameters
            filename = temp_directory + "/%s_%s_%s_%s_%s_batch_%s_page_%s.json" % (
                self.FILE_PREFIX, self.CONTAINER_SHA, start_time.strftime('%Y-%m-%d-%M-%S'), current_thread().getName(),
                os.getpid(), self.batch, self.CURRENT_PAGE_NUMBER)
            response = self.api_client.get(self.api_end_point, api_params, api.Client.XMLFileBufferedResponse(filename))
            return response
        else:
            qlogger.info("End of pagination for %s", self.OBJECT_TYPE)

    def _parse(self, file_name):
        parseresponse = {'next_batch_url': True}

        qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Started', self.OBJECT_TYPE, file_name)
        self._pre_parse()

        try:
            self._process_json_file(file_name)
        # if len(self.page_numbers) == 0:
        #	del parseresponse['next_batch_url'] # remove key to break the loop in run()
        except JSONDecodeError as e:
            qlogger.error("Failed to parse JSON API Output for endpoint %s. Message: %s", self.api_end_point, str(e))
        # if len(self.page_numbers) >= 1 and self.CURRENT_PAGE_NUMBER != 0:
        #	qlogger.error("Could not parse page number %d. Proceeding with next page number.", self.CURRENT_PAGE_NUMBER)
        #	self.page_numbers.pop(0)
        #	return {'next_batch_url': True}
        # else:
        #	return {}
        self._post_parse()

        qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Completed', self.OBJECT_TYPE, file_name)
        return parseresponse

    def _process_json_file(self, file_name):
        responseJson = json.load(open(file_name))
        try:
            data = responseJson['data']
            # for count of records fetched
            count = len(data)
            # for count of records in the count key of the json
            self.TOTAL_CONTAINERS = responseJson['count']

            if self.FIRST_PAGE:
                qlogger.info("Total %d containers to be processed in this run.", self.TOTAL_CONTAINERS)
                # self.list_page_numbers(self.TOTAL_CONTAINERS)
                self.FIRST_PAGE = False

            qlogger.info("Containers in page %d = %d", self.CURRENT_PAGE_NUMBER, count)

            prev_batch = self.last_updated_batch
            for container in data:
                # to queue imageId and uniqueKey (registry|repository)
                containerSha = container["sha"]
                if containerSha is None:
                    uuid = container["uuid"]
                    qlogger.debug("Found a record with sha:null. Corresponding uuid is %s", uuid)
                    self.NULL_CONTAINERS += 1
                    # have seen some records with 'None' container id.
                    # could be test data, but skip them.
                    continue

                qlogger.info("Container sha %s Parsing Started.", containerSha)
                
                # convert the epoch dates to human readable format
                container["created"] = convertTimeFormat(container["created"])
                container["stateChanged"] = convertTimeFormat(container["stateChanged"])
                container["updated"] = convertTimeFormat(container["updated"])
                prev_batch = container["updated"]
                """
                # Index the value in Splunk
                if self.cs_configuration.cs_log_individual_events:
                    event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SOURCETYPE)
                    event.data = json.dumps(container)
                    self.EVENT_WRITER.write_event(event)
                    self.LOGGED_CONTAINERS_COUNT = self.LOGGED_CONTAINERS_COUNT + 1
                qlogger.info("Container Id %s Parsing Completed.", containerId)
                """

                # put container id in cs_idset_queue
                self.cs_idset_queue.put(containerSha)
                qlogger.info("Pushing into queue: %s" % containerSha)
                self.checkpointData['last_run_datetime'] = container["updated"]

            if (self.page_size * (self.CURRENT_PAGE_NUMBER + 1) > 10000):
                self.batch += 1
                self.CURRENT_PAGE_NUMBER = 1
                self.last_updated_batch = self.cs_configuration.end_date
            else:
                self.CURRENT_PAGE_NUMBER += 1

            # self.page_numbers.pop(0)
            return True
        except Exception as e:
            qlogger.error("Could not process %s element. Error: %s", self.ROOT_TAG, str(e))
            return False
# End of QualysContainerPopulator class