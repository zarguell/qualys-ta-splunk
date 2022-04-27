__author__ = 'Qualys, Inc'
__copyright__ = "Copyright (C) 2021, Qualys, Inc"
__license__ = "New BSD"
__version__ = "1.0"

import time
from threading import current_thread
from collections import defaultdict
import six.moves.urllib.parse as urlpars

from lib.splunklib.modularinput import Event

import qualysModule
from qualysModule.splunkpopulator.basepopulator import BasePopulator
from qualysModule.splunkpopulator.basepopulator import BasePopulatorException
from qualysModule import *
from qualysModule.lib import api

from defusedxml import ElementTree as ET

import lxml.etree as LET
import xml.etree.ElementTree as XET
import re

class SemDetectionPopulatorConfiguration(object):
    _params_not_allowed = ['action', 'detection_updated_since', 'detection_updated_before', 'truncation_limit']

    def __init__(self, kbPopulator=None, logger=None):
        self.logger = logger
        self.sem_detection_api_filters = {}
        self.extra_sem_params = None
        self.log_sem_asset_summary = True
        self.log_individual_sem_detection = True
        self.batch = 1

    def add_sem_detection_api_filter(self, name, value, user_defined=False):
        if not user_defined or name not in self._params_not_allowed:
            self.sem_detection_api_filters[name] = value
        else:
            qlogger.warning(
                "Parameter %s with value %s was specified, but it is not allowed by TA. Not adding to API call.", name,
                value)


class SemDetectionPopulator(BasePopulator):
    PLUGINS = []
    OBJECT_TYPE = "SEM detection"
    FILE_PREFIX = "sem_detection"
    ROOT_TAG = 'ASSET'
    API = '/sem/v1/assetList'

    SOURCE = 'qualys'
    DETECTION_SOURCETYPE = 'qualys:sem:detection'
    SUMMARY_SOURCETYPE = 'qualys:sem:asset_summary'
    HOST = 'localhost'
    INDEX = 'main'

    def __init__(self, semDetectionConfiguration, event_writer):
        super(SemDetectionPopulator, self).__init__(semDetectionConfiguration.logger)
        self._sem_detection_api_filters = semDetectionConfiguration.sem_detection_api_filters
        self.log_sem_asset_summary = semDetectionConfiguration.log_sem_asset_summary
        self.log_individual_sem_detection = semDetectionConfiguration.log_individual_sem_detection
        self._batch = semDetectionConfiguration.batch
        self.truncation_limit = semDetectionConfiguration.truncation_limit
        self.extra_sem_params = semDetectionConfiguration.extra_sem_params
        self.asset_logged = 0
        self.HOST = semDetectionConfiguration.host
        self.INDEX = semDetectionConfiguration.index
        self.event_writer = event_writer

    @property
    def get_asset_logged_count(self):
        return self.asset_logged

    @property
    def get_api_parameters(self):
        return dict(list({"action": "list",'truncation_limit': self.truncation_limit}.items()) + list(self._sem_detection_api_filters.items()))

    @property
    def api_end_point(self):
        return self.API

    def _process_root_element(self, elem):
        detection_logged = 0

        if elem.tag == "ASSET":
            # Detection by severity
            detection_by_severity = {'SEVERITY_1': 0, 'SEVERITY_2': 0, 'SEVERITY_3': 0, 'SEVERITY_4': 0, 'SEVERITY_5': 0}

            # Detection by STATUS
            detection_by_status = {'New': 0, 'Active': 0, 'Fixed': 0, 'Reopened': 0}

            # Detection by TYPE
            detection_by_type = {'Potential': 0, 'Confirmed': 0, 'Information': 0}

            # Find the asset ID 
            asset_id = ""
            asset_id_elem = elem.find("ID")
            if asset_id_elem is not None:
                asset_id = asset_id_elem.text

            dl = elem.find('DETECTION_LIST')
            if dl is not None:
                if self.log_individual_sem_detection:
                    for detection in list(dl):
                        if detection.tag == "DETECTION":
                            # Add ASSET_ID at the begining of DETECTION tag
                            asset_id_tag = XET.Element('ASSET_ID')
                            asset_id_tag.text = asset_id
                            detection.insert(0,asset_id_tag)

                            # Move RESULTS tag at the end of event
                            results = detection.find("RESULTS")
                            if results is not None:
                                results_text = results.text
                                detection.remove(results)

                                new_results = XET.Element('RESULTS')
                                new_results.text = results_text
                                detection.append(new_results)

                            detection_xml_str = ET.tostring(detection).decode()

                            # Find the SEVERITY
                            severity_elem = detection.find("SEVERITY")
                            if severity_elem is not None:
                                severity = severity_elem.text
                                severity_key = 'SEVERITY_%s' % severity
                                detection_by_severity[severity_key] = detection_by_severity.get(severity_key, 0) + 1

                            # Find the STATUS
                            status_elem = detection.find("STATUS")
                            if status_elem is not None:
                                status = status_elem.text
                                detection_by_status[status] = detection_by_status.get(status, 0) + 1

                            # Find the TYPE
                            type_elem = detection.find("TYPE")
                            if type_elem is not None:
                                detection_type = type_elem.text
                                detection_by_type[detection_type] = detection_by_type.get(detection_type, 0) + 1

                            # Send the detection data to Splunk event 
                            event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.DETECTION_SOURCETYPE)
                            event.data = detection_xml_str
                            self.event_writer.write_event(event)

                            # Increment the detection logged count by 1
                            detection_logged += 1

                # Remove <DETECTION_LIST> tag for asset summary
                elem.remove(dl)

            if self.log_sem_asset_summary:                
                # Append SUMMARY_COUNTS tag
                summary_cnt_elem = XET.Element('SUMMARY_COUNTS')

                for severity_key in detection_by_severity:
                    severity = XET.Element(severity_key)
                    severity.text = str(detection_by_severity[severity_key])
                    summary_cnt_elem.append(severity)

                for status_key in detection_by_status:
                    status = XET.Element(status_key)
                    status.text = str(detection_by_status[status_key])
                    summary_cnt_elem.append(status)

                for type_key in detection_by_type:
                    detection_type = XET.Element(type_key)
                    detection_type.text = str(detection_by_type[type_key])
                    summary_cnt_elem.append(detection_type)

                elem.append(summary_cnt_elem)

                asset_xml_str = ET.tostring(elem).decode()

                # Send the asset summary data to Splunk event 
                event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SUMMARY_SOURCETYPE)
                event.data = asset_xml_str
                self.event_writer.write_event(event)

            # Increment the asset logged count by 1
            self.asset_logged += 1

        qlogger.info("ASSET_ID=%s parsing completed and logged %s detections.", asset_id, detection_logged)
        
        return detection_logged


    """
        The private method __fetch of BasePopulator class has override here.
        The purpose of this methond to convert API body params into URL params
        for SEM data input to call API endpoint with GET method.
    """


    def _BasePopulator__fetch(self, params=None):
        if self.api_end_point:
            api_params = self.get_api_parameters
            if params is not None:
                api_params = dict(list(api_params.items()) + list(params.items()))

            if '/sem/' in self.api_end_point:
                data = urlpars.urlencode(api_params)
                new_api_end_point = str(self.api_end_point) + "?" + str(data)
                api_params = {}

            filename = temp_directory + "/%s_%s_%s_%s_batch_%s.xml" % (
                self.FILE_PREFIX, start_time.strftime('%Y-%m-%d-%H-%M-%S'), current_thread().getName(), os.getpid(),
                self._batch)

            response = self.api_client.get(new_api_end_point, api_params, api.Client.XMLFileBufferedResponse(filename))
            return response
        else:
            raise Exception("API endpoint not set, when fetching values for Object type:%", self.OBJECT_TYPE)