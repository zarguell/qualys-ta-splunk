# -*- coding: utf-8 -*-
__author__ = "Qualys"
__copyright__ = "Copyright (C) 2018, Qualys"
__license__ = "New BSD"
__version__ = "1.1"
import random
import sys
from qualysModule.splunkpopulator.basepopulator import BasePopulator, BasePopulatorException
from collections import namedtuple
from qualysModule import qlogger
import csv
import json
from io import open
from lib.splunklib.modularinput import Event

from defusedxml import ElementTree as ET

from qualysModule import *

QualysQidStruct = namedtuple("QualysQid", "QID, SEVERITY")

class KnowledgebasePopulatorConfiguration:

    def __init__(self, logger=None):
        self.logger = logger
        self.knowledgebase_api_filters = {}
        
    def add_knowledgebase_api_filter(self, name, value):
            qlogger.info("Adding knowledgebase API parameter %s with value %s", name, value)
            self.knowledgebase_api_filters[name] = value
 
class QualysKnowledgebasePopulator(BasePopulator):
    OBJECT_TYPE = "knowledgebase"
    FILE_PREFIX = "kb"
    ROOT_TAG = 'VULN'
    SOURCE = 'qualys'
    SOURCETYPE = 'qualys:knowledgebase'
    HOST = 'localhost'
    INDEX = 'main'

    # extra fields to log with QID, by default QID_INFO and SEVERITY are already included

    QID_EXTRA_FIELDS_TO_LOG = ["DIAGNOSIS", "CONSEQUENCE", "SOLUTION"]
    QID_FIELDS_TO_LOG = ["VULN_TYPE", "PATCHABLE", "PCI_FLAG", "TITLE", "CATEGORY", "PUBLISHED_DATETIME"]
    BOOL_FIELDS = ["PATCHABLE", "PCI_FLAG"]

    CSV_HEADER_COLUMNS = ["QID", "SEVERITY"] + QID_FIELDS_TO_LOG + ["CVSS_BASE", "CVSS_TEMPORAL",
                                                                          "CVSS_VECTOR_STRING", "CVSS_V3_BASE",
                                                                          "CVSS_V3_TEMPORAL", "CVSS_V3_VECTOR_STRING",
                                                                          "CVE", "VENDOR_REFERENCE",
                                                                           "THREAT_INTEL_IDS", "THREAT_INTEL_VALUES", "BUGTRAQ_IDS"]

    def __init__(self, configuration, event_writer):
        super(QualysKnowledgebasePopulator, self).__init__(configuration.logger)
        self._qids = {}
        self._kbLoaded = False
        # only log QIDs greater than this value, to support incremental logs for Knowledgebase
        self.min_qid_to_log = 0
        self.qid_logged_cnt = 0
        self.log = True
        self.last_qid_logged = 0
        self.create_lookup_csv = False
        self.index_knowledgebase = False
        self._knowledgebase_api_filters = configuration.knowledgebase_api_filters
        self.HOST = configuration.host
        self.INDEX = configuration.index
        self.EVENT_WRITER = event_writer

    @property
    def get_qid_logged_count(self):
        return self.qid_logged_cnt

    @property
    def qids(self):
        return self._qids

    @property
    def api_end_point(self):
        return "/api/2.0/fo/knowledge_base/vuln/"

    @property
    def get_api_parameters(self):
        return dict(list({"action": "list", "details": "Basic"}.items()) + list(self._knowledgebase_api_filters.items()))

    def _process_root_element(self, elem):
        logged = False
        qid = int(elem.find('QID').text)

        if qid is not None:
            severity = int(elem.find('SEVERITY_LEVEL').text)
            qid_dict = {'QID': qid, 'SEVERITY': severity, 'CVSS_BASE':'', 'CVSS_TEMPORAL':'', 'CVSS_VECTOR_STRING':'', 'CVSS_V3_BASE':'', 'CVSS_V3_TEMPORAL':'', 'CVSS_V3_VECTOR_STRING':'', 'THREAT_INTEL_IDS':'', 'THREAT_INTEL_VALUES': '', 'BUGTRAQ_IDS':''}

            for sub_ele in list(elem):
                name = sub_ele.tag
                if name in self.CSV_HEADER_COLUMNS:
                    val = sub_ele.text
                    if name in ['TITLE', 'CATEGORY', 'DIAGNOSIS', 'CONSEQUENCE', 'SOLUTION'] and val is not None:
                        if sys.version_info[0] < 3:
                            val = sub_ele.text.replace('"', '\'').encode('utf-8')
                        else:
                            val = sub_ele.text.replace('"', '\'')
                    elif name in self.BOOL_FIELDS:
                        val = 'YES' if val == '1' else 'NO'
                    qid_dict[name] = val

                elif name == 'CVSS':
                    for sub_tag in list(sub_ele):
                        csv_header = 'CVSS_%s' % sub_tag.tag
                        if csv_header in self.CSV_HEADER_COLUMNS:
                           qid_dict[csv_header] = sub_tag.text
                elif name == 'CVSS_V3':
                    for sub_tag in list(sub_ele):
                        cvss_header = 'CVSS_V3_%s' % sub_tag.tag
                        if cvss_header in self.CSV_HEADER_COLUMNS:
                            qid_dict[cvss_header] = sub_tag.text
                elif name == 'CVE_LIST':
                    cves = []
                    for cve_node in list(sub_ele):
                        cves.append(cve_node.find('ID').text)
                    if len(cves) > 0:
                        # sort by CVE id in reverse order so that latest CVE is first
                        cves.sort(reverse=True)
                        qid_dict['CVE'] = ', '.join(cves)
                elif name == 'THREAT_INTELLIGENCE':
                    threat_intel_ids = []
                    threat_intel_values = []
                    for sub_tag in list(sub_ele):
                        if(sub_tag.tag == "THREAT_INTEL"):
                            if sys.version_info[0] < 3:
                                threat_intel_values.append(sub_tag.text.encode('utf-8'))
                            else:
                                threat_intel_values.append(sub_tag.text)
                            threat_intel_ids.append(sub_tag.attrib['id'])
                    qid_dict['THREAT_INTEL_IDS'] = ", ".join(threat_intel_ids)
                    qid_dict['THREAT_INTEL_VALUES'] = ", ".join(threat_intel_values)
                elif name == 'VENDOR_REFERENCE_LIST':
                    vendor_refs = []
                    for vendor_ref_node in list(sub_ele):
                        vendor_refs.append(vendor_ref_node.find('ID').text)
                    if len(vendor_refs) > 0:
                        # sort by CVE id in reverse order so that latest CVE is first
                        vendor_refs.sort(reverse=True)
                        qid_dict['VENDOR_REFERENCE'] = ', '.join(vendor_refs)
                elif name == 'BUGTRAQ_LIST':
                    bugList = []
                    for b_node in list(sub_ele):
                        bugList.append(b_node.find('ID').text)
                    if len(bugList) > 0:
                        qid_dict['BUGTRAQ_IDS'] = ', '.join(bugList)

            self._qids[qid] = qid_dict

        return logged

    def get_last_qid_logged(self):
        return self.last_qid_logged

    def get_vuln_log_line(self, vuln_struct):
        """

        :param vuln_struct QualysQidStruct:
        :return:
        """
        return "QID_INFO: QID=%s SEVERITY=%s TITLE=\"%s\" CATEGORY=\"%s\"" \
               % (vuln_struct.QID, vuln_struct.SEVERITY, vuln_struct.TITLE, vuln_struct.CATEGORY)

    def get_qid_severity(self, qid):
        qid = int(qid)
        if qid in self._qids and 'SEVERITY' in self._qids[qid]:
            return self._qids[qid]['SEVERITY']
        else:
            return None

    """
    Create lookup CSV file here, since self._qids should now contain all the QID
    """

    def _post_parse(self):
        if self.create_lookup_csv:
            TA_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
            lookup_destination = TA_ROOT + '/lookups/qualys_kb.csv'
            qlogger.info("Update lookup file: %s with %s QIDs", lookup_destination, len(self._qids))

            if sys.version_info[0] < 3:
                mode  = 'wb'
            else:
                mode  = 'w'

            with open(lookup_destination, mode) as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.CSV_HEADER_COLUMNS)
                writer.writeheader()
                for qid in self._qids:
                    writer.writerow(self._qids[qid])
            qlogger.info("Updated lookup file: %s with %s QIDs", lookup_destination, len(self._qids))
        elif self.index_knowledgebase:
            for qid in self._qids:
                event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SOURCETYPE)
                event.data = json.dumps(self._qids[qid])
                self.EVENT_WRITER.write_event(event)
                self.qid_logged_cnt += 1

            qlogger.info("Logged %s QIDs", self.qid_logged_cnt)