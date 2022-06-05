__author__ = 'Qualys, Inc'
# -*- coding: utf-8 -*-
__copyright__ = "Copyright (C) 2017, Qualys, Inc"
__license__ = "New BSD"
__version__ = "1.0"

import os
import csv
import time
import json
from collections import defaultdict
from xml.sax.saxutils import escape
import re
import traceback

from qualysModule.splunkpopulator.basepopulator import BasePopulator, BasePopulatorException
from collections import namedtuple
from qualysModule import qlogger
import qualysModule.splunkpopulator.utils
from qualysModule.splunkpopulator.utils import evalAfterCheckpoint
from qualysModule.splunkpopulator.detectionpopulator import HostDetectionPopulatorConfiguration

from defusedxml import ElementTree as ET

from qualysModule import *
from lib.splunklib.modularinput import Event
import lxml.etree as LET

class PolicyPopulatorConfiguration(HostDetectionPopulatorConfiguration):
    _params_not_allowed = ["action", "details", "updated_after_datetime", "show_remediation_info", "cause_of_failure", "include_dp_name"]

    def __init__(self, logger):
        self.logger = logger
        self.policy_api_parameters = {}
        self.batch = 1

    def add_policy_api_filter(self, name, value, user_defined=False):
        if not user_defined or name not in self._params_not_allowed:
            qlogger.info("Adding Policy API extra parameter %s with value %s", name, value)
            self.policy_api_parameters[name] = value
        else:
            qlogger.warning("Parameter %s is not allowed by Policy Populator. Not adding to API call.", name)


# class PolicyPopulatorConfiguration

class PosturePopulatorConfiguration(PolicyPopulatorConfiguration):
    _params_not_allowed = ["action", "output_format", "details", "status_changes_since",
						   "policy_ids", "show_remediation_info", "cause_of_failure", "include_dp_name", "policy_id", "truncation_limit"]

    def __init__(self, logger):
        self.logger = logger
        self.posture_api_parameters = {}
        self.batch = 1

    def add_posture_api_filter(self, name, value, user_defined=False):
        if not user_defined or name not in self._params_not_allowed:
            qlogger.info("Adding Posture Information API extra parameter %s with value %s", name, value)
            self.posture_api_parameters[name] = value
        else:
            qlogger.warning("Parameter %s is not allowed by Posture Information Populator. Not adding to API call.",
                            name)

    def get_posture_api_param_value(self, param_name):
        if param_name in self.posture_api_parameters:
            return self.posture_api_parameters[param_name]
        else:
            return None


# class PosturePopulatorConfiguration

class QualysPolicyPopulator(BasePopulator):
	OBJECT_TYPE = "Policy Compliance"
	FILE_PREFIX = "policy"
	ROOT_TAG = "POLICY"
	SOURCE = 'qualys'
	SOURCETYPE = 'qualys:pc:policyInfo'
	HOST = 'localhost'
	INDEX = 'main'

	def __init__(self, policy_configuration, policy_idset_queue, event_writer,num_count_for_pid):
		super(QualysPolicyPopulator, self).__init__(policy_configuration.logger)
		self.policy_configuration = policy_configuration
		self.policy_idset_queue = policy_idset_queue
		self._policy_ids = set()
		self.LOGGED = 0
		self.HOST = policy_configuration.host
		self.INDEX = policy_configuration.index
		self.EVENT_WRITER = event_writer
		self.num_count_for_pid = int(num_count_for_pid)

	@property
	def api_end_point(self):
		return "/api/2.0/fo/compliance/policy/"

	@property
	def get_api_parameters(self):
		return dict(list({
			"action": "list",
			"details": "Basic"
			}.items()) + list(self.policy_configuration.policy_api_parameters.items()))

	def _process_root_element(self, elem):
		try:
			policy_id = elem.find('ID').text
			policy_last_evaluated_datetime = elem.find('LAST_EVALUATED').find('DATETIME').text
			if evalAfterCheckpoint(policy_last_evaluated_datetime, self.policy_configuration.checkpoint_datetime):
				policy_title = elem.find('TITLE').text
				policy_created_datetime = elem.find('CREATED').find('DATETIME').text
				policy_created_by = elem.find('CREATED').find('BY').text
				policy_last_modified_datetime = elem.find('LAST_MODIFIED').find('DATETIME').text
				policy_last_modified_by = elem.find('LAST_MODIFIED').find('BY').text
				policy_status = elem.find('STATUS').text
				policy_is_locked = elem.find('IS_LOCKED').text
				# add policy id into a set, which later ends up in self.policy_idset_queue
				self._policy_ids.add(policy_id)
				event_list = []
				event_list.append("POLICY_ID=\"%s\"" % policy_id)
				event_list.append("POLICY_TITLE=\"%s\"" % policy_title)
				event_list.append("LAST_EVALUATED_DATETIME=\"%s\"" % policy_last_evaluated_datetime)
				event_list.append("LAST_MODIFIED_DATETIME=\"%s\"" % policy_last_modified_datetime)
				event_list.append("LAST_MODIFIED_BY=\"%s\"" % policy_last_modified_by)
				event_list.append("CREATED_DATETIME=\"%s\"" % policy_created_datetime)
				event_list.append("CREATED_BY=\"%s\"" % policy_created_by)
				event_list.append("STATUS=\"%s\"" % policy_status)
				event_list.append("IS_LOCKED=\"%s\"" % policy_is_locked)
				events = "POLICY_INFO: %s" % ", ".join(event_list)
				event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SOURCETYPE)
				event.data = events
				self.EVENT_WRITER.write_event(event)
				# self.output(self.getEventXML(event))
				self.LOGGED += 1
				return True
			else:
				qlogger.debug(
					"Skipping policy id %s because it is evaluated BEFORE checkpoint %s. It might have been indexed in during last run.",
					policy_id, self.policy_configuration.checkpoint_datetime)
				return False

		except Exception as e:
			qlogger.error("Could not process %s element. Error: %s", self.ROOT_TAG, str(e))
			return False

	def _post_parse(self):
		qlogger.info("Adding policy ids into policy_idset_queue")
		# User can provide the count between 1 to 10
		# as posture info api accepts min 1 & max 10 policy ids at a time! Default will be 1.

		policyIdsList = list(self._policy_ids)
		numPolicyIds = len(policyIdsList)
        
		numChunks = numPolicyIds / self.num_count_for_pid

		if numPolicyIds % self.num_count_for_pid != 0:
			numChunks += 1
		
		idChunks = qualysModule.splunkpopulator.utils.chunks(policyIdsList, numChunks)
		idChunksList = list(idChunks)
		finalIdChunksList = list(filter(None, idChunksList))
        
		for idChunk in finalIdChunksList:
			self.policy_idset_queue.put(",".join(idChunk))
		self._policy_ids = set()

class ThreadedPostureInfoPopulator(BasePopulator):
	OBJECT_TYPE = "Policy Compliance Posture Information"
	FILE_PREFIX = "policy_posture"
	ROOT_TAG = "RESPONSE"
	SOURCE = 'qualys'
	SOURCETYPE = 'qualys:pc:postureInfo'
	HOST = 'localhost'
	INDEX = 'main'
	ids = None
	LOGGED = 0
	HOST_DICT = {}
	CONTROL_DICT = {}
	TECHNOLOGY_DICT = {}
	TP_DICT = {}
	FV_DICT = {}
	DPD_DICT = {}
	TM_DICT = {}
	pc_truncation_limit = 0

	def __init__(self, ids, event_writer, postureConfiguration):
		super(ThreadedPostureInfoPopulator, self).__init__(postureConfiguration.logger)
		self.posture_configuration = postureConfiguration
		self.ids = ids
		self.LOGGED = 0
		self.HOST = postureConfiguration.host
		self.INDEX = postureConfiguration.index
		self.EVENT_WRITER = event_writer
		self.details = self.posture_configuration.details
		self.extra_details = self.posture_configuration.extra_details
		self.pc_truncation_limit = postureConfiguration.pc_truncation_limit
		self._batch = postureConfiguration.batch
	# end of __init__

	@property
	def api_end_point(self):
		return "/api/2.0/fo/compliance/posture/info/"

	@property
	def get_api_parameters(self):
		try:
			type = "Basic"
			extra_detail = {}

			if self.details:
				type = "All"

			if self.extra_details:
				type = "All"
				extra_detail = {"show_remediation_info":1, "cause_of_failure":1, "include_dp_name":1}

			base_params = {
				"action": "list",
				"details": type,
				"output_format": "xml",
                "truncation_limit": self.pc_truncation_limit
			}
 
			base_params = self.merge_two_dicts(base_params, extra_detail)
			return dict(list(base_params.items()) + list(self.posture_configuration.posture_api_parameters.items()) + list({
				'policy_id': self.ids}.items()))
		except Exception as e:
			qlogger.error("Error: %s", str(e))
		# get_api_parameters

	def merge_two_dicts(self, x, y):
		z = x.copy()  # start with x's keys and values
		z.update(y)  # modifies z with y's keys and values & returns None
		return z

	@property
	def get_logged_controls_count(self):
		return self.LOGGED

	def _parse(self, file_name):
		qlogger.info('OBJECT="%s" FILENAME="%s" Parsing Started.', self.OBJECT_TYPE, file_name)
		total = 0
		logged = 0
		response = {'error': False}
		load_next_batch = False
		next_url = None

		self._pre_parse()
		try:
			context = qualysModule.splunkpopulator.utils.xml_iterator(file_name)
			_, root = next(context)
			# print "<stream>"
			for event, elem in context:
				if elem.tag == self.ROOT_TAG:
					total += 1
					if self._process_root_element(elem):
						logged += 1
					elem.clear()
				elif elem.tag == "WARNING":
					warning_code = elem.find('CODE').text
					if warning_code == "1980":
						load_next_batch = True
						next_url = elem.find('URL')
					elem.clear()
				root.clear()
				# print "</stream>"
		except LET.XMLSyntaxError as e:
			qlogger.error("Failed to parse invalid xml response. Message: %s", str(e))
			try:
				os.rename(file_name, file_name + ".errored")
				qlogger.info("Renamed response filename with : %s", file_name + ".errored")
			except Exception as err:
				qlogger.error("Could not rename errored xml response filename. Reason: %s", err.message)
			return {"retry": True, "message":str(e)}
		except ET.ParseError as e:
			# self.output("ERROR %s", str(e))
			qlogger.warning("Failed to parse API Output for endpoint %s. Message: %s", self.api_end_point, str(e))
			try:
				os.rename(file_name, file_name + ".errored")
				qlogger.info("Renamed response filename with : %s", file_name + ".errored")
			except Exception as err:
				qlogger.error("Could not rename errored xml response filename. Reason: %s", err.message)
			# Return the Exception message to the parent function
			return {"retry": True, "message":str(e)}
		self._post_parse()
		qlogger.info("Parsed %d %s entry. Logged=%d", total, self.OBJECT_TYPE, logged)
		qlogger.info('OBJECT="%s" FILENAME="%s" Parsing Completed.', self.OBJECT_TYPE, file_name)

		if load_next_batch and next_url is not None:
			self._batch += 1
			if not self.preserve_api_output:
				qlogger.debug("Removing tmp file " + file_name)
				try:
					os.remove(file_name)
				except OSError:
					pass
			else:
				qlogger.debug("Not removing tmp file " + file_name)
			qlogger.info("Found truncation warning, auto loading next batch from url:%s" % next_url.text)
			next_batch_params = qualysModule.splunkpopulator.utils.get_params_from_url(next_url.text)
			response['next_batch_params'] = next_batch_params
			return response
		else:
			qlogger.debug("Done with parsing, returning.")
			return response

	def _process_root_element(self, elem):
		policy_summary_list = []
		controls_by_status = {}
		number_of_controls = 0
		try:
			if elem.tag == self.ROOT_TAG:
				policy_id = self.ids
				qlogger.info("POLICY_ID=%s Parsing Started.",policy_id)
				info_list = elem.find('INFO_LIST')
				self.create_host_dict(elem, './/GLOSSARY/HOST_LIST/HOST', policy_id)
				self.create_control_dict(elem, './/GLOSSARY/CONTROL_LIST/CONTROL', policy_id)
				if self.details:
					self.create_technology_dict(elem, './/GLOSSARY/TECHNOLOGY_LIST/TECHNOLOGY', policy_id)
				if self.extra_details:
					self.create_technology_dict(elem, './/GLOSSARY/TECHNOLOGY_LIST/TECHNOLOGY', policy_id)
					self.TP_DICT = self.create_value_dict(elem, './/GLOSSARY/TP_LIST/TP', policy_id, "V")
					self.FV_DICT = self.create_value_dict(elem, './/GLOSSARY/FV_LIST/FV', policy_id, "V")
					self.DPD_DICT = self.create_value_dict(elem, './/GLOSSARY/DPD_LIST/DPD', policy_id, "NAME")
					self.TM_DICT = self.create_tm_dict(elem, './/GLOSSARY/TM_LIST/TM', policy_id)

				if info_list is not None:
					for info_elem in list(info_list):
						host_id = info_elem.find('HOST_ID').text
						control_id = info_elem.find('CONTROL_ID').text
						technology_id = info_elem.find('TECHNOLOGY_ID').text
						status = info_elem.find('STATUS').text
						posture_modified_date = info_elem.find('POSTURE_MODIFIED_DATE').text

						event_list = []
						event_list.append("POLICY_ID=\"%s\"" % policy_id)
						#Host details
						event_list.append("HOST_ID=\"%s\"" % host_id)
						if self.HOST_DICT.get(host_id) is not None:
							event_list.append(self.get_log_line_from_dict(self.HOST_DICT.get(host_id)))
						# Control details
						event_list.append("CONTROL_ID=\"%s\"" % control_id)
						if self.CONTROL_DICT.get(control_id) is not None:
							data = defaultdict(list)
							data_list = ["CRITICALITY_VALUE", "CRITICALITY_LABEL", "CONTROL_STATEMENT", "CONTROL_REFERENCE", str(technology_id)]
							control = self.CONTROL_DICT.get(control_id)
							for key, value in list(control.items()):
								if key in data_list:
									if key == str(technology_id):
										data["RATIONALE_TECHNOLOGY_ID"] = key
										data["RATIONALE_TEXT"] = value
									else:
										data[key] = value

							event_list.append(self.get_log_line_from_dict(data))
						# Technology details
						event_list.append("TECHNOLOGY_ID=\"%s\"" % technology_id)
						if (self.details or self.extra_details) and self.TECHNOLOGY_DICT.get(technology_id) is not None:
							event_list.append(self.get_log_line_from_dict(self.TECHNOLOGY_DICT.get(technology_id)))
						event_list.append("STATUS=\"%s\"" % status)
						event_list.append("POSTURE_MODIFIED_DATE=\"%s\"" % posture_modified_date)

						if self.extra_details:
							if info_elem.find('REMEDIATION') != None:
								remediation = info_elem.find('REMEDIATION')
								event_list.append("REMEDIATION=\"%s\"" % self.clean_data(remediation) if remediation is not None else '')
							else:
								qlogger.debug("CONTROL_ID=%s has no REMEDIATION info for POLICY_ID=%s.", control_id, policy_id)

							if info_elem.find('CAUSE_OF_FAILURE') != None:
								cause_of_failure_dict = self.get_cause_of_failure(info_elem.find('CAUSE_OF_FAILURE'))
								for k, v in list(cause_of_failure_dict.items()):
									cause_of_failure_data = (str(k) + "=\"" + ' | '.join(v) + "\"")
									event_list.append(cause_of_failure_data)
							else:
								qlogger.debug("CONTROL_ID=%s has no CAUSE_OF_FAILURE info for POLICY_ID=%s.", control_id, policy_id)

							if info_elem.find('EVIDENCE') != None:
								evidence_dict = self.get_evidence(info_elem.find('EVIDENCE'))
								if evidence_dict != None:
									for k, v in list(evidence_dict.items()):
										evidence_data = (str(k) + "=\"" + v + "\"")
										event_list.append(evidence_data)
							else:
								qlogger.debug("CONTROL_ID=%s has no EVIDENCE info for POLICY_ID=%s.", control_id,
												policy_id)

						events_list = "POSTURE_INFO: %s" % ", ".join(event_list)

						if self.posture_configuration.log_individual_events:
							event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SOURCETYPE)
							event.data = events_list
							self.EVENT_WRITER.write_event(event)
						number_of_controls += 1
						if status in controls_by_status:
							controls_by_status[status] += 1
						else:
							controls_by_status[status] = 1
						self.LOGGED += 1
				else:
					qlogger.warning("POLICY_ID=%s No info element found in XML.",policy_id)

				policy_summary_list.append("POLICY_ID=\"%s\"" % policy_id)
				policy_summary_list.append("NUMBER_OF_CONTROLS=\"%s\"" % number_of_controls)
				policy_summary_list.append(self.get_log_line_from_dict(controls_by_status))
				summary_event = "POLICY_SUMMARY: %s" % ", ".join(policy_summary_list)

				if self.posture_configuration.log_summary_events:
					event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE, sourcetype=self.SOURCETYPE)
					event.data = summary_event
					self.EVENT_WRITER.write_event(event)
				qlogger.info("POLICY_ID=%s Parsing Completed.", policy_id)
				return True
		except Exception as e:
			qlogger.error("Could not process %s element. Error: %s | traceback - %s", self.ROOT_TAG, str(e), traceback.format_exc())
			return False

	def get_log_line_from_dict(self, dict_obj):
		return ', '.join("%s=\"%s\"" % (str(key), str(val)) for (key, val) in list(dict_obj.items()))

	def clean_data(self, value):
		return escape(' '.join(value.text.split()).replace("\"", "\'").replace("\\'", "'")) if value.text is not None else ''
		# return value.replace('"', "'").replace("\\'", "'").replace("\t", "").replace("  ", "").replace("\n", "")

	def create_host_dict(self, elem, xpath, policy_id):
		try:
			elemt_list = elem.findall(xpath)
			for host in elemt_list:
				id = host.find("ID").text
				if id is not None and id not in list(self.HOST_DICT.keys()):
					ip = self.clean_data(host.find("IP")) if host.find("IP") is not None else ''
					dns = self.clean_data(host.find("DNS")) if host.find("DNS") is not None else ''
					self.HOST_DICT[id] = {"HOST_IP": ip, "HOST_DNS": dns}
				else:
					pass
		except Exception as e:
			list_name = xpath.rsplit('/', 2)
			qlogger.error("Could not process %s for Policy_Id=%s. Error: %s | traceback - %s", list_name[1], policy_id, str(e),traceback.format_exc())

	def create_control_dict(self, elem, xpath, policy_id):
		try:
			self.CONTROL_DICT = {}
			elemt_list = elem.findall(xpath)
			for control in elemt_list:
				id = control.find("ID").text
				if id is not None and id not in list(self.CONTROL_DICT.keys()):
					statement = self.clean_data(control.find("STATEMENT")) if control.find("STATEMENT") is not None else ''
					reference = self.clean_data(control.find("REFERENCE")) if control.find("REFERENCE") is not None else ''
					label = self.clean_data(control.find("./CRITICALITY/LABEL")) if control.find("./CRITICALITY/LABEL") is not None else 'Unknown'
					value = self.clean_data(control.find("./CRITICALITY/VALUE")) if control.find("./CRITICALITY/VALUE") is not None else 'Unknown'
					self.CONTROL_DICT[id] = {"CONTROL_STATEMENT": statement, "CONTROL_REFERENCE": reference,
															"CRITICALITY_LABEL": label, "CRITICALITY_VALUE": value}
				#add RATIONALE value in control dict
				if self.extra_details:
					rationale_list = control.find("RATIONALE_LIST")
					if rationale_list is not None:
						for rationale_elem in list(rationale_list):
							rationale_text = self.clean_data(rationale_elem.find('./TEXT')) if rationale_elem.find('./TEXT') is not None else ''
							rationale_tech_id = self.clean_data(rationale_elem.find('./TECHNOLOGY_ID')) if rationale_elem.find('./TECHNOLOGY_ID') is not None else ''
							self.CONTROL_DICT[id][rationale_tech_id] = rationale_text
		except Exception as e:
			list_name = xpath.rsplit('/', 2)
			qlogger.error("Could not process %s for Policy_Id=%s. Error: %s | traceback - %s", list_name[1], policy_id, str(e),traceback.format_exc())

	def create_technology_dict(self, elem, xpath, policy_id):
		technology_name = ""
		try:
			technology_list = elem.findall(xpath)
			for technology in technology_list:
				id = technology.find("ID").text
				if id is not None and id not in list(self.TECHNOLOGY_DICT.keys()):
					if technology.find("NAME") is not None:
						technology_name = self.clean_data(technology.find("NAME")) if technology.find("NAME") is not None else ''
					self.TECHNOLOGY_DICT[id] = {"TECHNOLOGY_NAME": technology_name}
				else:
					pass
		except Exception as e:
			list_name = xpath.rsplit('/', 2)
			qlogger.error("Could not process %s for Policy_Id=%s. Error: %s | traceback - %s", list_name[1], policy_id, str(e),traceback.format_exc())

	def get_cause_of_failure(self, tree):
		try:
			data = defaultdict(list)
			cof = "CAUSE_OF_FAILURE_"
			for cause_of_failure in tree.findall("./"):
				for v in cause_of_failure.findall("./"):
					data_v = "%s" % self.clean_data(v) if v.text is not None else ''
					data[cof + cause_of_failure.tag].append(data_v)
				if cause_of_failure.tag == 'MISSING':
					logic_data  ="%s" % str(cause_of_failure.attrib['logic']) if cause_of_failure.attrib['logic'] else ''
					data[cof + cause_of_failure.tag + "_LOGIC"].append(logic_data)
			return data
		except Exception as e:
			qlogger.error("Could not get the CAUSE_OF_FAILURE. Error: %s", str(e))

	def get_evidence(self, tree):
		dp_regex = '(:dp_[^\s]+)'
		fv_regex = '(#fv_[^\s]+)'
		tp_regex = '(\$tp_[^\s]+)'
		v_data = []
		fv_l = []
		tp_l = []
		dp_l = []
		last_updated = "lastUpdated:%s"
		evidence = "Expected Value(s) - "
		evidence_dpd_name = ""
		data = defaultdict(list)
		try:
			bool_expr = str(tree.find("./BOOLEAN_EXPR").text)
			tp_key = self.get_key_value(tp_regex, bool_expr)
			fv_key = self.get_key_value(fv_regex, bool_expr)
			dp_key = self.get_key_value(dp_regex, bool_expr)

			for dpv_list_from_evid in tree.findall("./DPV_LIST"):
				dpv_list = dpv_list_from_evid.getchildren()
				if len(dpv_list) > 0:
					for dpv in dpv_list:
						if 'lastUpdated' not in dpv.attrib:
							lastUpdated = 'lastUpdated:NA'
						elif dpv.attrib['lastUpdated'] is not None:
							lastUpdated = str(last_updated % (str(dpv.attrib['lastUpdated'])))

						val_list = dpv.findall("V")
						if len(val_list) > 1:
							for v in val_list:
								cleaned_v = self.clean_data(v)
								data_v = self.get_data_value(cleaned_v, lastUpdated)
								v_data.append(data_v)
						else:
							got_v = dpv.find("V")
							cleaned_v = ''
							if got_v is not None:
								cleaned_v = self.clean_data(got_v)
							data_v = self.get_data_value(cleaned_v, lastUpdated)
							v_data.append(data_v)
			evidence_current_value = str(" ==OR== ".join(v_data) if v_data else '')

			if fv_key:
				for fv1 in fv_key:
					fv_l.append((self.FV_DICT.get(fv1) if (fv1 and self.FV_DICT.get(fv1)) not in ['', ' ', None] else ''))
			if tp_key:
				for tp1 in tp_key:
					tp_l.append((self.TP_DICT.get(tp1) if (tp1 and self.TP_DICT.get(tp1)) not in ['', ' ', None] else ''))
			f = set([_f for _f in fv_l if _f])
			fv = " ==OR== ".join(f)
			t = set([_f for _f in tp_l if _f])
			tp = " ==OR== ".join(t)

			len_f = len(f)
			len_t = len(t)

			if len_f>=1 and len_t>=1:
				evidence += fv +" ==OR== "+ tp
			elif len_f>=1 and len_t<1:
				evidence += fv
			elif len_f<1 and len_t>=1:
				evidence += tp
			elif len_f<1 and len_t< 1:
				pass

			evidence += " | Current Values(s) - "
			evidence += evidence_current_value

			if dp_key:
				for dp in dp_key:
					dp_l.append(self.DPD_DICT.get(dp) if (dp and self.DPD_DICT.get(dp)) not in ['', ' ', None] else '')
			evidence_dpd_name += " ==OR== ".join(set([_f for _f in dp_l if _f]))

			data["EVIDENCE"] = evidence
			data["EVIDENCE_CURRENT_VALUE"] = evidence_current_value
			data["EVIDENCE_DPD_NAME"] = evidence_dpd_name
			return data
		except Exception as e:
			qlogger.error("Could not get the EVIDENCE. Error: %s  | traceback - %s", str(e), traceback.format_exc())

	def create_value_dict(self, elem, xpath, policy_id, value):
		DICT = {}
		v = ""
		try:
			elemt_list = elem.findall(xpath)
			for i in list(elemt_list):
				if i.find(value) is not None:
					d = []
					val_list = i.findall(value)
					if len(val_list) > 1:
						for j in val_list:
							d.append(self.clean_data(j))
						v = " ==OR== ".join(d)
					else:
						v = self.clean_data(i.find(value))
				DICT[i.find("LABEL").text] = v
			return DICT
		except Exception as e:
			list_name = xpath.rsplit('/', 2)
			qlogger.error("Could not process %s for Policy_Id=%s. Error: %s | traceback - %s", list_name[1], policy_id, str(e), traceback.format_exc())

	def create_tm_dict(self, elem, xpath, policy_id):
		DICT = {}
		try:
			tm_list = elem.findall(xpath)
			for tm in list(tm_list):
				if tm.find("PAIR") is not None:
					for key_val in list(tm.findall("PAIR")):
						DICT[self.clean_data(key_val.find("K"))] = self.clean_data(key_val.find("V"))
			return DICT
		except Exception as e:
			list_name = xpath.rsplit('/', 2)
			qlogger.error("Could not process %s for Policy_Id=%s. Error: %s | traceback - %s", list_name[1], policy_id, str(e), traceback.format_exc())

	def get_key_value(self, key_regular_expression, boolean_expr):
		try:
			compiled_value = re.compile(key_regular_expression)
			if bool(re.search(compiled_value, boolean_expr)):
				find_all = re.findall(compiled_value, boolean_expr)
				de_duplicated_list = set(find_all)
				return list(de_duplicated_list)
			else:
				return list()
		except Exception as e:
			import traceback
			qlogger.error("Could not get the dp or fv or tp value from BOOLEAN EXPRESSION. Error: %s | traceback - %s", str(e), traceback.format_exc())

	def get_data_value(self, v, lastUpdated):
		if v in list(self.TM_DICT.keys()):
			return (self.TM_DICT.get(v) + " == " + lastUpdated)
		else:
			return((v + " == " + lastUpdated) if v not in [None, ''] else lastUpdated)
# end of class ThreadedPostureInfoPopulator
