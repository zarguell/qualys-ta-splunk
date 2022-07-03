# -*- coding: utf-8 -*-
__author__ = "Bharat Patel"
__copyright__ = "Copyright (C) 2014, Bharat Patel"
__license__ = "New BSD"
__version__ = "1.0"

import time
from threading import current_thread
from collections import defaultdict

from lib.splunklib.modularinput import Event

import qualysModule
from qualysModule.splunkpopulator.qid_plugins import *
from qualysModule.splunkpopulator.basepopulator import BasePopulator
from qualysModule.splunkpopulator.basepopulator import BasePopulatorException
from qualysModule import *

from defusedxml import ElementTree as ET

import lxml.etree as LET
import re

HOST_FIELD_MAPPINGS = {"ID": "HOST_ID"}
HOST_FIELD_TO_MAP = ["ID"]

# #These fields can have special characters or text in other languages to change to them to Utf-8
fields_to_encode = ["OS", "DNS", "NETBIOS"]

QIDParser.load_plugins()

class HostDetectionPopulatorConfiguration(object):
    _params_not_allowed = ['action', 'output_format', 'vm_processed_after', 'ids', 'suppress_duplicated_data_from_csv',
                           'max_days_since_last_vm_scan', 'max_days_since_vm_scan']

    def __init__(self, kbPopulator=None, logger=None):
        self.logger = logger
        self.detection_api_filters = {}
        self.collect_advanced_host_summary = True
        self.log_host_summary = True
        self.log_host_detections = True
        self.log_host_details_in_detection = True  # Log extra Host information with each host detection event e.g. IP, DNS, NetBIOS OS etc
        self.batch = 1
        self.kb_populator = kbPopulator
        self.full_pull_enabled = False
        self.seed_file_enabled = False
        self.detection_fields_to_log = ""
        self.host_fields_to_log = ""
        self.max_allowed_results_field_len = 0

    def add_detection_api_filter(self, name, value, user_defined=False):
        if not user_defined or name not in self._params_not_allowed:
            qlogger.info("Adding Detection API parameter %s with value %s", name, value)
            self.detection_api_filters[name] = value
        else:
            qlogger.warning(
                "Parameter %s with value %s was specified, but it is not allowed by TA. Not adding to API call.", name,
                value)

class WASDetectionPopulatorConfiguration(HostDetectionPopulatorConfiguration):
    _validFilters = ['id', 'qid', 'name', 'type', 'url', 'status', 'patch',
                     'webApp.tags.id', 'webApp.tags.name', 'webApp.id', 'webApp.name',
                     'severity', 'ignoredDate', 'ignoredReason', 'group',
                     'owasp.name', 'owasp.code',
                     'wasc.name', 'wasc.code', 'cwe.id',
                     'firstDetectedDate', 'lastDetectedDate', 'lastTestedDate', 'timesDetected']

    def __init__(self, kbPopulator=None, logger=None):
        super(WASDetectionPopulatorConfiguration, self).__init__(kbPopulator, logger)
        self.api_filters_list = []
        self.detection_api_filters = "<ServiceRequest><filters></filters></ServiceRequest>"
        self.api_preferences = "<preferences><verbose>true</verbose></preferences>"
        self.log_was_detections = True
        self.log_was_summary = True

    #  __init__

    def add_detection_api_filter(self, name, operator, value):
        if name in self._validFilters:
            criteriaTag = "<Criteria field=\"%s\" operator=\"%s\">" % (name, operator)

            sameFieldOperatorCriteria = [criteria for criteria in self.api_filters_list if criteriaTag in criteria]
            for matchingItem in sameFieldOperatorCriteria:
                self.api_filters_list.remove(matchingItem)
            # end of for loop

            criteriaXML = "%s%s</Criteria>" % (criteriaTag, value)
            self.api_filters_list.append(criteriaXML)

            detection_criteria = ''
            for criteria in self.api_filters_list:
                detection_criteria += criteria

            self.detection_api_filters = "<ServiceRequest>%s<filters>%s</filters></ServiceRequest>" % (
                self.api_preferences, detection_criteria)
        else:
            qlogger.warn("%s - Tried to add an unsupported detection API parameter '%s'.", type(self).__name__, name)
        # add_detection_api_filter


# class WASDetectionPopulatorConfiguration

class HostDetectionPopulator(BasePopulator):
    PLUGINS = []
    OBJECT_TYPE = "detection"
    FILE_PREFIX = "host_detection"
    ROOT_TAG = 'HOST'

    SOURCE = 'qualys'
    SOURCETYPE = 'qualys:hostDetection'
    HOST = 'localhost'
    INDEX = 'main'

    def __init__(self, detectionConfiguration, event_writer):
        """
		@type detectionConfiguration: HostDetectionPopulatorConfiguration
		"""
        # whether or not to break down count of Vulns by Severity and Status and Type, in HOSTSUMMARY events
        # by default we only break down counts by Severity levels
        super(HostDetectionPopulator, self).__init__(detectionConfiguration.logger)
        self._detection_api_filters = detectionConfiguration.detection_api_filters
        self.collect_advanced_host_summary = detectionConfiguration.collect_advanced_host_summary
        self.log_host_summary = detectionConfiguration.log_host_summary
        self.log_host_detections = detectionConfiguration.log_host_detections
        self.log_host_details_in_detection = detectionConfiguration.log_host_details_in_detection
        self._batch = detectionConfiguration.batch
        self._kb_populator = detectionConfiguration.kb_populator
        self.truncation_limit = detectionConfiguration.truncation_limit
        self.host_logged = 0
        self.HOST = detectionConfiguration.host
        self.INDEX = detectionConfiguration.index
        self.full_pull_enabled = detectionConfiguration.full_pull_enabled
        self.seed_file_enabled = detectionConfiguration.seed_file_enabled
        self.detection_fields_to_log = detectionConfiguration.detection_fields_to_log
        self.host_fields_to_log = detectionConfiguration.host_fields_to_log
        self.max_allowed_results_field_len = detectionConfiguration.max_allowed_results_field_len 
        self.event_writer = event_writer

    @property
    def get_host_logged_count(self):
        return self.host_logged

    @property
    def get_api_parameters(self):
        return dict(list({"action": "list", "show_igs": 1, "show_results": 0,
                     'truncation_limit': self.truncation_limit}.items()) + list(self._detection_api_filters.items()))

    @property
    def api_end_point(self):
        return "/api/2.0/fo/asset/host/vm/detection/"

    def _process_root_element(self, elem):
        # Convert host fields to log from string to list
        host_fields_to_log_list = self.host_fields_to_log.split(',')

        # Remove whitespace from each host field & create a final list
        host_fields_to_log_final_list = [host_field_elem.strip() for host_field_elem in host_fields_to_log_list]

        # Convert detection fields to log from string to list
        detection_fields_to_log_list = self.detection_fields_to_log.split(',')

        # Remove whitespace from each detection field & create a final list
        detection_fields_to_log_final_list = [detection_field_elem.strip() for detection_field_elem in detection_fields_to_log_list]

        if elem.tag == "HOST":
            plugin_output = []
            host_summary = []
            vulns_by_type = {'POTENTIAL': 0, 'CONFIRMED': 0}
            vulns_by_status = {'ACTIVE': 0, 'NEW': 0, 'FIXED': 0, 'RE-OPENED': 0}
            vulns_by_severity = {}
            other_stats = {}
            host_vuln_count = 0
            type_by_status = {'CONFIRMED_ACTIVE':0,'CONFIRMED_NEW':0,'CONFIRMED_FIXED':0,'CONFIRMED_RE-OPENED':0,'CONFIRMED_-':0,
                              'POTENTIAL_ACTIVE':0,'POTENTIAL_NEW':0,'POTENTIAL_FIXED':0,'POTENTIAL_RE-OPENED':0,'POTENTIAL_-':0,
                              'INFO_-': 0}

            host_id = None
            for sub_ele in list(elem):
                name = sub_ele.tag
                if name == "ID":
                    host_id = sub_ele.text
                    name = "HOST_ID"
                    host_summary.append("HOST_ID=" + host_id)

                if name in host_fields_to_log_final_list:
                    if name == "TAGS":
                        host_tags = []
                        tag_elements = sub_ele.findall('./TAG/NAME')
                        for tag_element in list(tag_elements):
                            host_tags.append(tag_element.text.replace("\"", "\'").replace("\n", ""))
                        # for
                        val = ",".join(host_tags)
                        
                    elif name == "CLOUD_PROVIDER_TAGS":
                        cloud_tags = []
                        tag_elements = sub_ele.findall('CLOUD_TAG')
                        for tag_element in list(tag_elements):
                            cloud_tag_value = tag_element.find("VALUE")
                            if cloud_tag_value is not None:
                                cloud_tag_value = cloud_tag_value.text.replace("\"", "\'").replace("\n", "")
                                cloud_tags.append(cloud_tag_value)
                        val= ",".join(cloud_tags)
                    # tags parsing ends here

                    else:
                        val = sub_ele.text.replace("\"", "\'").replace("\n", "")

                    if name in fields_to_encode:
                        if sys.version_info[0] < 3:
                            val = val.encode('utf-8')
                        else:
                            val = val
                    host_summary.append("%s=\"%s\"" % (name, val))

            if not host_id:
                qlogger.error("Unable to find host_id")
                return False
            
            metadata_summary = []
            metadata_list = elem.find('METADATA')
            if metadata_list is not None:
                metadata_attributes = ['LAST_STATUS', 'LAST_SUCCESS_DATE', 'LAST_ERROR_DATE', 'LAST_ERROR']
                for metadata in list(metadata_list):
                    for attribute in list(metadata):
                        ec2_attribute_name = attribute.find('NAME')
                        if ec2_attribute_name is not None:
                            ec2_attribute_name = ec2_attribute_name.text.replace("\"", "\'").replace("\n", "")
                            attr = ec2_attribute_name.split("/")
                            ec2_attribute_name = attr[-1]
                        ec2_attribute_value = attribute.find('VALUE')
                        if ec2_attribute_value is not None and ec2_attribute_value.text is not None:
                            ec2_attribute_value = ec2_attribute_value.text.replace("\"", "\'").replace("\n", "")
                        else:
                            ec2_attribute_value = ""
                        metadata_summary.append("%s=\"%s\"" % (ec2_attribute_name, ec2_attribute_value))
                        for a in metadata_attributes:
                            ec2_attribute = attribute.find(a)
                            if ec2_attribute is not None:
                                if ec2_attribute.text is not None:
                                    ec2_attribute = ec2_attribute.text.replace("\"", "\'").replace("\n", "")
                                    metadata_summary.append("%s_%s=\"%s\"" % (ec2_attribute_name, a.lower(), ec2_attribute))
                                else:
                                    metadata_summary.append("%s_%s=\"%s\"" % (ec2_attribute_name, a.lower(), ""))
            host_summary = host_summary + metadata_summary
            host_line = ", ".join(host_summary)
            dl = elem.find('DETECTION_LIST')
            if dl is not None:
                for detection in list(dl):
                    vuln_summary = []
                    vuln_results_field = ""
                    is_results_field = False
                    qid_node = detection.find('QID')
                    if qid_node is not None:
                        host_vuln_count += 1
                        qid = int(qid_node.text)
                        _type = detection.find('TYPE').text.upper()
                        status_element = detection.find('STATUS')
                        if status_element is not None:
                            status = detection.find('STATUS').text.upper()
                        else:
                            status = "-"

                        severity = detection.find('SEVERITY')
                        if severity is not None:
                            severity = severity.text
                        else:
                            severity = self.get_qid_severity(qid)

                        if severity:
                            severity_key = 'SEVERITY_%s' % severity
                            vuln_summary.append('SEVERITY=%s' % severity)

                            vulns_by_severity[severity_key] = vulns_by_severity.get(severity_key, 0) + 1
                            if self.collect_advanced_host_summary:
                                # Break down, count of vulns by each severity and each status, type
                                type_severity_key = '%s_%s' % (_type, severity_key)
                                status_severity_key = '%s_%s' % (status, severity_key)
                                other_stats[type_severity_key] = other_stats.get(type_severity_key, 0) + 1
                                other_stats[status_severity_key] = other_stats.get(status_severity_key, 0) + 1
                                # type_by_status will be collected
                                if status not in ['', None]: type_by_status["%s_%s" % (_type, str(status))] += 1
                        for sub_ele in list(detection):
                            name = sub_ele.tag
                            val = sub_ele.text.upper() if not name == "RESULTS" else sub_ele.text

                            if name == 'TYPE':
                                vulns_by_type[val] = vulns_by_type.get(val, 0) + 1

                            if name == 'STATUS':
                                vulns_by_status[val] = vulns_by_status.get(val, 0) + 1

                            if name in detection_fields_to_log_final_list:
                                if (name == "RESULTS"):
                                    is_results_field = True
                                    vuln_results_field = re.sub('\n', 'NEW_LINE_CHAR', val)
                                    vuln_results_field = re.sub('\t', 'TAB_CHAR', vuln_results_field)
                                    vuln_results_field = re.sub('\s+', ' ', vuln_results_field).strip(' ')
#                                    vuln_results_field = re.sub('\s+', ' ', val).strip(' ')

                                if (name != "RESULTS"):
                                    vuln_summary.append("%s=\"%s\"" % (name, val))

                        if self.log_host_detections:
                            # Output HOSTVULN line
                            host_id_line = "HOSTVULN: "

                            if not self.log_host_details_in_detection:
                                host_id_line = "HOSTVULN: HOST_ID=%s," % host_id
                            else:
                                host_id_line = "HOSTVULN: %s," % host_line

                            if is_results_field:
                                result_truncated = 0
                                vuln_results_field_len = len(vuln_results_field) + len(', RESULTS=""')
                                
                                if self.max_allowed_results_field_len > 0 and vuln_results_field_len > self.max_allowed_results_field_len:
                                    static_result_content = len(' [TRUNCATED Characters] ')
                                    truncated_chars = (vuln_results_field_len + static_result_content) - self.max_allowed_results_field_len
                                    actual_truncated_chars = truncated_chars + len(str(truncated_chars))                                   
                                    vuln_results_field = vuln_results_field[:int(vuln_results_field_len - actual_truncated_chars)] + " [TRUNCATED "+str(actual_truncated_chars)+" Characters]"
                                    result_truncated = 2
                                    
                                if self.hd_event_truncate_limit > 0:
                                    total_event_len_wo_result = len("%s %s" % (host_id_line, ", ".join(vuln_summary)))
                                    vuln_results_field_len = len(vuln_results_field)+len(', RESULTS=""')
                                    total_event_len = int(total_event_len_wo_result+vuln_results_field_len+len(', RESULT_TRUNCATED="0"'))

                                    if total_event_len > self.hd_event_truncate_limit:
                                        result_truncated = 1

                                vuln_summary.append("%s=\"%s\"" % ("RESULT_TRUNCATED", result_truncated))
                                vuln_summary.append("%s=\"%s\"" % ("RESULTS", vuln_results_field))

                            if self.seed_file_enabled:
                                self.output("%s %s" % (host_id_line, ", ".join(vuln_summary)))
                            else:
                                event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE,
                                              sourcetype=self.SOURCETYPE)
                                event.data = "%s %s" % (host_id_line, ", ".join(vuln_summary))
                                self.event_writer.write_event(event)

                        p_output = QIDParser.process(qid, host_id, detection, self._logger)
                        if p_output and p_output != "":
                            plugin_output.append(p_output)

            if self.log_host_summary:

                host_summary = ["HOSTSUMMARY: %s" % host_line, self.get_log_line_from_dict(vulns_by_severity),
                                self.get_log_line_from_dict(vulns_by_type),
                                self.get_log_line_from_dict(vulns_by_status),
                                self.get_log_line_from_dict(type_by_status)]

                if self.collect_advanced_host_summary:
                    host_summary.append(self.get_log_line_from_dict(other_stats))
                if plugin_output:
                    host_summary.append(", ".join(plugin_output))

                host_summary.append("TOTAL_VULNS=%s" % host_vuln_count)
                if self.seed_file_enabled:
                    self.output(", ".join(host_summary))
                else:
                    event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SOURCETYPE)
                    event.data = "%s %s" % ('', ", ".join(host_summary))
                    self.event_writer.write_event(event)

            self.host_logged += 1

            return True
        # _process_root_element

    def get_qid_severity(self, qid):
        if self._kb_populator:
            return self._kb_populator.get_qid_severity(qid)

    @staticmethod
    def get_log_line_from_dict(dict_obj):
        return ', '.join("%s=%r" % (key, val) for (key, val) in list(dict_obj.items()))

class WASDetectionPopulator(HostDetectionPopulator):
    PLUGINS = []
    OBJECT_TYPE = "WAS detection"
    FILE_PREFIX = "was_detection"
    ROOT_TAG = 'Finding'
    SOURCETYPE = 'qualys:wasFindings'
    SOURCE = 'qualys'
    HOST = 'localhost'
    INDEX = 'main'

    def __init__(self, detectionConfiguration, event_writer):
        super(WASDetectionPopulator, self).__init__(detectionConfiguration, event_writer)
        self.detectionConfiguration = detectionConfiguration
        self.webAppSummaryDict = {}
        self.event_writer = event_writer

    # __init__

    @property
    def get_host_logged_count(self):
        return self.host_logged

    # get_host_logged_count

    @property
    def get_api_parameters(self):
        return self.detectionConfiguration.detection_api_filters

    # get_api_parameters

    @property
    def api_end_point(self):
        return "/qps/rest/3.0/search/was/finding"

    # api_end_point

    def printWebAppSummary(self):
        for webAppId, summary in list(self.webAppSummaryDict.items()):
            subData = []
            for key, value in list(summary.items()):
                subData.append("%s=\"%s\"" % (key, value))

            data = "WAS_SUMMARY: webapp_id=\"%s\", %s" % (webAppId, ", ".join(subData))

            event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SOURCETYPE)
            event.data = data
            self.event_writer.write_event(event)
        # print self.createEventXML(data)

    # end of printWebAppSummary

    def run(self):
        super(WASDetectionPopulator, self).run()

        if self.log_host_summary:
            self.printWebAppSummary()

    # run

    def get_next_batch_params(self, lastId):
        self.detectionConfiguration.add_detection_api_filter('id', 'GREATER', str(lastId))
        return self.detectionConfiguration.detection_api_filters

    # get_next_batch_params

    def _parse(self, file_name):
        qlogger.info("Parsing %s XML", self.OBJECT_TYPE)
        total = 0
        logged = 0
        response = {'error': False}
        load_next_batch = False
        lastId = 0
        next_batch_params = None

        self._pre_parse()
        try:
            context = qualysModule.splunkpopulator.utils.xml_iterator(file_name)

            for event, elem in context:

                if elem.tag == "responseCode":
                    code = elem.text
                    qlogger.info("API Response Code = %s", code)

                    if code != 'SUCCESS':
                        response['error_code'] = code
                        response['error_message'] = code
                        for ev, el in context:
                            if (el.tag == "errorMessage"):
                                response['error_message'] = el.text
                        raise BasePopulatorException(
                            "API ERROR. Code={0} Message={1}".format(response['error_code'], response['error_message']))
                    elem.clear()
                if elem.tag == self.ROOT_TAG:
                    total += 1
                    if self._process_root_element(elem):
                        logged += 1
                    elem.clear()

                elif elem.tag == "hasMoreRecords" and elem.text == 'true':
                    qlogger.info("Batch %d fetched.There are more records to be fetched", self._batch)
                    load_next_batch = True
                    elem.clear()

                if load_next_batch and elem.tag == "lastId":
                    lastId = elem.text
                    # if
                    next_batch_params = self.get_next_batch_params(lastId)
        except LET.XMLSyntaxError as e:
            qlogger.error("Failed to parse invalid xml response. Message: %s", str(e))
            try:
                os.rename(file_name, file_name + ".errored")
                qlogger.info("Renamed response filename with : %s", file_name + ".errored")
            except Exception as err:
                qlogger.error("Could not rename errored xml response filename. Reason: %s", err.message)
            return {"retry": True, "message":str(e)}
        except ET.ParseError as e:
            qlogger.error("Failed to parse API Output for endpoint %s. Message: %s", self.api_end_point, str(e))
            self.output("ERROR %s", str(e))
            return {"retry": True, "message":str(e)}
        self._post_parse()
        qlogger.info("Parsed %d %s entry. Logged=%d", total, self.OBJECT_TYPE, logged)
        if load_next_batch and next_batch_params is not None:
            self._batch += 1
            if not self.preserve_api_output:
                qlogger.debug("Removing tmp file " + file_name)
                try:
                    os.remove(file_name)
                except OSError:
                    pass
            else:
                qlogger.debug("Not removing tmp file " + file_name)
            response['next_batch_params'] = next_batch_params;
            return response
        else:
            return response

    # _parse

    def _process_root_element(self, elem):
        detection_fields_to_log = ['id', "qid", "name", "type", "severity", "url", "status", "firstDetectedDate",
                                   "lastDetectedDate", "lastTestedDate", "timesDetected", "cwe"]
        host_fields_to_log = ["ID", "IP", "TRACKING_METHOD", "DNS", "NETBIOS", "OS", "LAST_SCAN_DATETIME"]
        web_app_fields_to_log = ["id", "name", "url"]

        if elem.tag == WASDetectionPopulator.ROOT_TAG:
            plugin_output = []
            host_summary = []

            finding = []
            webApp = []

            vulnType = ''
            vulnStatus = '-'
            vulnSeverity = ''
            other_stats = {}
            host_vuln_count = 0

            host_id = None

            for sub_ele in list(elem):
                name = sub_ele.tag

                if name in detection_fields_to_log:
                    if name == 'id':
                        finding_id = sub_ele.text
                        finding.append("finding_id=\"%s\"" % finding_id)
                    elif name == 'url':
                        url = sub_ele.text.replace('"', '%22')
                        finding.append("%s=\"%s\"" % (name, url))
                    elif name == "cwe":
                        cwe_list = []
                        cwe_elements = sub_ele.findall('./list/long')
                        for cwe_element in list(cwe_elements):
                            cwe_list.append(cwe_element.text.replace("\"", "\'").replace("\n", ""))
                        val = ",".join(cwe_list)
                        finding.append("%s=\"%s\"" % (name, val))
                    else:
                        finding.append("%s=\"%s\"" % (name, sub_ele.text.replace("\"", "\'").replace("\n", "")))
                        if name == 'type':
                            vulnType = sub_ele.text
                        elif name == 'status':
                            vulnStatus = sub_ele.text
                        elif name == 'severity':
                            vulnSeverity = sub_ele.text
                        # end of if-elif ladder
                elif name == 'webApp':
                    for webApp_ele in list(sub_ele):
                        if webApp_ele.tag == 'id':
                            webApp.append("webapp_id=\"%s\"" % webApp_ele.text)
                            webAppId = webApp_ele.text
                        elif webApp_ele.tag == 'url':
                            webapp_url = webApp_ele.text.replace('"', '%22')
                            webApp.append("webapp_url=\"%s\"" % webapp_url)
                        elif webApp_ele.tag == 'name':
                            webApp.append("webapp_name=\"%s\"" % webApp_ele.text.replace("\"", "\'").replace("\n", ""))
                        elif webApp_ele.tag == "tags":
                            tags = []
                            tag_elements = webApp_ele.findall('./list/Tag/name')
                            for tag_element in list(tag_elements):
                                tags.append(tag_element.text.replace("\"", "\'").replace("\n", ""))
                            # for
                            val = ",".join(tags)
                            webApp.append("tags=\"%s\"" % val)
                        else:
                            webApp.append("%s=\"%s\"" % (webApp_ele.tag, webApp_ele.text))
                        # end of else
                        # end of for
                        # if
            # for
            if vulnStatus == '-':
                finding.append("status=\"-\"")

            # populate dictionary for web app summary
            if webAppId not in self.webAppSummaryDict:
                summary = defaultdict(int)
                summary['type_VULNERABILITY'] = 0
                summary['type_SENSITIVE_CONTENT'] = 0
                summary['type_INFORMATION_GATHERED'] = 0
                summary['status_-'] = 0
                summary['status_NEW'] = 0
                summary['status_ACTIVE'] = 0
                summary['status_FIXED'] = 0
                summary['status_REOPENED'] = 0
                summary['severity_1'] = 0
                summary['severity_2'] = 0
                summary['severity_3'] = 0
                summary['severity_4'] = 0
                summary['severity_5'] = 0
				
                self.webAppSummaryDict[webAppId] = summary
            # if
            self.webAppSummaryDict[webAppId]['type_' + vulnType] += 1
            self.webAppSummaryDict[webAppId]['status_' + vulnStatus] += 1
            self.webAppSummaryDict[webAppId]['severity_' + vulnSeverity] += 1

            if self.log_host_detections:
                event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SOURCETYPE)
                event.data = "WAS_FINDING: %s, %s" % (", ".join(webApp), ", ".join(finding))
                self.event_writer.write_event(event)
            # print self.getEventXML(webApp, finding)

            self.host_logged += 1
        # if

        return True

    # _process_root_element

# class WASDetectionPopulator
