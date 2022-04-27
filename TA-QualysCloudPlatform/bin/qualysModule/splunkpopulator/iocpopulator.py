# -*- coding: utf-8 -*-
__author__ = 'Qualys, Inc'
__copyright__ = "Copyright (C) 2018, Qualys, Inc"
__license__ = "New BSD"
__version__ = "1.0"

import os
import csv
import time
import datetime as DT
import json
import six.moves.urllib.request as urlreq, six.moves.urllib.parse as urlpars, six.moves.urllib.error as urlerr
from threading import current_thread

from qualysModule.splunkpopulator.basepopulator_json import BasePopulatorJson, BasePopulatorJsonException
from collections import namedtuple
from qualysModule import qlogger

from threading import current_thread
from qualysModule.lib import api

from qualysModule import *
from lib.splunklib.modularinput import Event
from io import open

"""Indicator of Compromise Events Populator Configuration"""
class IocEventsPopulatorConfiguration(object):
    _params_not_allowed = ["dateTime", "pageNumber", "pageSize","fromDate", "toDate"]

    def __init__(self, logger):
        self.logger = logger
        self.ioc_extra_params = None
        self.fromDate = '1999-01-01T00:00:00Z'
        self.checkpointData = None
        self.checkpoint = None
        # self.lastScanned = 'dateTime>='

    def add_ioc_api_filter(self, extra_params, user_defined=False):
        try:
            qlogger.info("Adding EDR Events API extra parameter -  %s", extra_params)
            self.ioc_extra_params = extra_params
        except Exception as e:
            qlogger.warning("Exception: EDR API filter - %s", str(e))

"""Indicator of Compromise Events Count"""
class IOCEventsCount(BasePopulatorJson):
    OBJECT_TYPE = "EDR Events Count"
    FILE_PREFIX = "edr_events_count"
    API = "/ioc/events/count"

    def __init__(self, ioc_config):
        super(IOCEventsCount, self).__init__(ioc_config.logger)
        self.ioc_config = ioc_config
        self.COUNT = 0
        self.fromDate = self.ioc_config.fromDate
        self.toDate = self.ioc_config.toDate

    @property
    def get_events_count(self):
        return self.COUNT

    @property
    def api_end_point(self):
        try:
            sort = urlpars.quote('[{"event.datetime":"asc"}]')
            endpoint = "%s?&sort=%s&state=false" % (self.API, sort)
            filterDateRange = urlpars.quote("(event.datetime:['%s'..'%s'])" % (str(self.fromDate), str(self.toDate)))
            endpoint = "%s&filter=%s" % (endpoint, filterDateRange)
            if self.ioc_config.ioc_extra_params not in ("", None):
                extra_param = urlpars.quote(" AND (%s)" % (self.ioc_config.ioc_extra_params))
                return endpoint + extra_param
            else:
                return endpoint
        except Exception as e:
            qlogger.error("Error while making api endpoint. ERROR:%s",str(e))

    def _parse(self, file_name):
        parseresponse = {'next_batch_url': True}
        qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Started', self.OBJECT_TYPE, file_name)
        self._pre_parse()
        try:
            self._process_json_file(file_name)
            parseresponse['next_batch_url'] = False
        except Exception as e:
            qlogger.error("Failed to parse JSON API Output for endpoint %s. Message: %s", self.api_end_point, str(e))
            return {}
        self._post_parse()
        qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Completed', self.OBJECT_TYPE, file_name)
        return parseresponse

    # End of _parse method

    def _process_json_file(self, file_name):
        try:
            responseJson = json.load(open(file_name))
            self.COUNT = responseJson['count']
            qlogger.info("Total count of EDR Events to fetch - %s.", self.COUNT)
            return True
        except Exception as e:
            qlogger.error("Could not process data. Error: %s", str(e))
            return False
# End of IOCEventsCount class

"""Indicator of Compromise Events Populator"""
class IOCEventsPopulator(BasePopulatorJson):
    OBJECT_TYPE = "EDR"
    FILE_PREFIX = "edr_events"
    API = "/ioc/events"
    SOURCE = 'qualys'
    SOURCETYPE = 'qualys:edr:event'
    FIRST_PAGE = True # changes to False after first page (page 0) is processed

    def __init__(self, event_writer, ioc_config):
        super(IOCEventsPopulator, self).__init__(ioc_config.logger)
        self.ioc_config = ioc_config
        self.LOGGED = 0
        self.pageSize = int(ioc_config.pageSize)
        self.fromDate = self.ioc_config.fromDate
        self.toDate = self.ioc_config.toDate
        # self.pageNumber = [0]
        self.EVENT_WRITER = event_writer
        self.HOST = ioc_config.host
        self.INDEX = ioc_config.index
        self.TOTAL_EVENTS = ioc_config.events_count
        self.CURRENT_PAGE_NUMBER = 0
        self.batch = 1
        self.checkpointData = ioc_config.checkpointData
        self.checkpoint = ioc_config.checkpoint

    @property
    def get_logged_events_count(self):
        return self.LOGGED

    @property
    def last_record_dateTime(self):
        return self.toDate

    @property
    def api_end_point(self):
        try:
            sort = urlpars.quote('[{"event.datetime":"asc"}]')
            filterDateRange = urlpars.quote("(event.datetime:['%s'..'%s'])" % (str(self.fromDate), str(self.toDate)))
            # self.CURRENT_PAGE_NUMBER = self.pageNumber[0]
            qlogger.info("Downloading pageNumber: %d of batch: %d", self.CURRENT_PAGE_NUMBER, self.batch)
            endpoint = "%s?&sort=%s&pageSize=%d&pageNumber=%d&state=false" % (self.API, sort, self.pageSize, self.CURRENT_PAGE_NUMBER)
            endpoint = "%s&filter=%s" % (endpoint, filterDateRange)
            if self.ioc_config.ioc_extra_params not in ("", None):
                extra_param = urlpars.quote(" AND (%s)" % (self.ioc_config.ioc_extra_params))
                return endpoint + extra_param
                # ("%sAND %s" % (endpoint, urllib.quote(self.ioc_config.ioc_extra_params)))
            else:
                return endpoint
        except Exception as e:
            qlogger.error("Error while making api endpoint. ERROR:%s", str(e))

    # def list_page_numbers(self, number_of_events):
    #     required_api_calls = int(number_of_events / self.pageSize)
    #     rem = number_of_events % self.pageSize
    #     if rem > 0:
    #         required_api_calls = required_api_calls + 1
    #     qlogger.info("TA need to make %d more API calls to get list of all events.", required_api_calls)
    #     self.pageNumber.extend(list(range(1, required_api_calls)))
    #     qlogger.info("Page numbers list updated for getting events list API call.")

    def _parse(self, file_name):
        parseresponse = {'next_batch_url': True}
        qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Started', self.OBJECT_TYPE, file_name)
        self._pre_parse()
        try:
            parseresponse = self._process_json_file(file_name)
            # if len(self.pageNumber) == 0:
            #     del parseresponse['next_batch_url']  # remove key to break the loop in run()
        except JSONDecodeError as e:
            qlogger.error("Failed to parse JSON API Output for endpoint %s. Message: %s", self.api_end_point, str(e))
            # if len(self.pageNumber) >= 1 and self.CURRENT_PAGE_NUMBER != 0:
            #     qlogger.error("Could not parse page number %d. Proceeding with next page number.",
            #                   self.CURRENT_PAGE_NUMBER)
            #     self.pageNumber.pop(0)
            #     return {'next_batch_url': True}
            # else:
            #     return {}
        self._post_parse()
        qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Completed', self.OBJECT_TYPE, file_name)
        return parseresponse

    def _fetch(self):
        api_params = {}
        api_end_point = self.api_end_point
        if api_end_point:
            filename = temp_directory + "/%s_%s_%s_PID_%s_Batch_%d_page_%s.json" % (
                self.FILE_PREFIX, start_time.strftime('%Y-%m-%d-%H-%M-%S'), current_thread().getName(), os.getpid(),
                self.batch, self.CURRENT_PAGE_NUMBER)
            # filename = temp_directory + "/%s_%s_%s_PID_%s_Batch_%d_page_%s.json" % (
            #     self.FILE_PREFIX, start_time.strftime('%Y-%m-%d-%H-%M-%S'), current_thread().getName(), os.getpid(), self.batch, self.pageNumber[0])
            response = self.api_client.get(api_end_point, api_params, api.Client.XMLFileBufferedResponse(filename))
            return response
        else:
            raise Exception("API endpoint not set, when fetching values for Object type:%", self.OBJECT_TYPE)

    def _process_json_file(self, file_name):
        try:
            count_events_per_api_call = 0
            responseJson = json.load(open(file_name))
            if not responseJson:
                return {}
            if self.FIRST_PAGE:
                # qlogger.info("Total %d events to be processed in this run.", self.TOTAL_EVENTS)
                #self.list_page_numbers(self.TOTAL_EVENTS)
                self.FIRST_PAGE = False
            # qlogger.debug(self.pageNumber)
            checkpointDateTime = None
            for eventData in responseJson:
                eventId = eventData["id"]
                eventData["dateTime"] = DT.datetime.strptime(eventData["dateTime"], "%Y-%m-%dT%H:%M:%S.%f+0000").strftime('%Y-%m-%dT%H:%M:%SZ')
                checkpointDateTime = eventData["dateTime"]
                if eventId is None:
                    qlogger.debug("Found a record with id:null.")
                    continue
                qlogger.debug("Event Id %s Parsing Started.", eventId)
                # Index the value in Splunk
                event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SOURCETYPE)
                event.data = json.dumps(eventData)
                self.EVENT_WRITER.write_event(event)
                self.LOGGED += 1
                count_events_per_api_call += 1
                qlogger.debug("Event Id %s Parsing Completed.", eventId)
            qlogger.info("Total events indexed in this API call - %d", count_events_per_api_call)
            count_events_per_api_call = 0
            #if self.pageSize * (self.CURRENT_PAGE_NUMBER + 1) >= 10000 and not epochDate > self.toDate:
            if self.pageSize * (self.CURRENT_PAGE_NUMBER + 1) >= 10000:
                self.CURRENT_PAGE_NUMBER = 0
                self.fromDate = checkpointDateTime
                self.batch +=1
                self.checkpointData['last_run_datetime'] = checkpointDateTime
                self.saveCheckpoint()
                qlogger.info("Updating EDR Events Information checkpoint to %s"%(self.checkpointData['last_run_datetime']))
            else:
                self.CURRENT_PAGE_NUMBER += 1
            #self.pageNumber.pop(0)
            return {'next_batch_url': True}
        except Exception as e:
            qlogger.error("Could not process data. Error: %s", str(e))
            return {}
# End of IOCEventsPopulator class
