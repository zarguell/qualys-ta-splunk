__author__ = 'Prabhas Gupte'

import six.moves.queue as Queue, os
from qualysModule.splunkpopulator.basepopulator import BasePopulator
from qualysModule import qlogger
import qualysModule.splunkpopulator.utils
import splunk.clilib.cli_common as scc

from defusedxml import ElementTree as ET

class webAppIdFetcher(BasePopulator):
	OBJECT_TYPE = "webAppIdFetcher"
	FILE_PREFIX = "web_app_ids"
	ROOT_TAG = 'WebApp'
	ID_TAG = 'id'
	ids = []

	def __init__(self, appIdQueue):
		super(webAppIdFetcher, self).__init__()
		self.appIdQueue = appIdQueue
		self.lastId = None
	# end of __init__

	@property
	def get_api_parameters(self):
		api_params = ''
		qualysConf = scc.getMergedConf("qualys")
		if self.lastId:
			api_params = "<Criteria field=\"id\" operator=\"%s\">%s</Criteria>" % ('GREATER', self.lastId)
		if 'extra_was_params' in qualysConf['setupentity'] and qualysConf['setupentity']['extra_was_params'] != '':
			extra_params_root = ET.fromstring(qualysConf['setupentity']['extra_was_params'])
			for child in extra_params_root:
				child_attribs = child.attrib
				if child_attribs['field'] == 'webApp.id':
					api_params += "<Criteria field=\"id\" operator=\"%s\">%s</Criteria>" % (child_attribs['operator'], child.text)
				# if
			# for
		if api_params != '':
			return "<ServiceRequest><filters>" + api_params + "</filters></ServiceRequest>"
		else:
			return ''
	# end of get_api_parameters

	def _parse(self, file_name):
		qlogger.info('OBJECT="%s" FILENAME="%s" Parsing Started.', self.OBJECT_TYPE, file_name)
		total = 0
		logged = 0
		response = {'error': False}
		load_next_batch = False
		self.lastId = None
		

		self._pre_parse()
		try:
			context = qualysModule.splunkpopulator.utils.xml_iterator(file_name)
			_, root = next(context)
			for event, elem in context:

				if elem.tag == "RESPONSE":
					code = elem.find('CODE')
					if code is not None:
						response['error_code'] = code.text
						response['error_message'] = elem.find('TEXT').text
						# Send to ET.ParseError instead of raising to BasePopulatorException so we can return and retry
						raise ET.ParseError("API ERROR. Code= {0}, Message= {1}".format(response['error_code'],
																							   response[
																								   'error_message']))
					elem.clear()
				# Internal Errors resulting in a 999 response will be DOCTYPE GENERIC_RETURN
				elif elem.tag == "GENERIC_RETURN":
					code = elem.find('RETURN')
					if code is not None:
						if "Internal error" in code.text:
							response['error_code'] = code.text
							response['error_message'] = code.text
							#Send to ET.ParseError instead of raising to BasePopulatorException so we can return and retry
							raise ET.ParseError("API Error - Found Internal Error. Clean up and Retry")
					elem.clear()
				elif elem.tag == self.ROOT_TAG:
					total += 1
					if self._process_root_element(elem):
						logged += 1
					elem.clear()

				elif elem.tag == "hasMoreRecords" and elem.text == "true":
					load_next_batch = True
				elif elem.tag == "lastId":
					self.lastId = elem.text
				root.clear()
				# print "</stream>"
		except ET.XMLSyntaxError as e:
			qlogger.error("Failed to parse invalid xml response. Message: %s", str(e))
			try:
				os.rename(file_name, file_name + ".errored")
				qlogger.info("Renamed response filename with : %s", file_name + ".errored")
			except Exception as err:
				qlogger.error("Could not rename errored xml response filename. Reason: %s", err.message)
			return str(e)
		except ET.ParseError as e:
			#self.output("ERROR %s", str(e))
			qlogger.error("Failed to parse API Output for endpoint %s. Message: %s", self.api_end_point, str(e))
			#Return the Exception message to the parent function
			return str(e)
		self._post_parse()
		qlogger.info("Parsed %d %s entry. Logged=%d", total, self.OBJECT_TYPE, logged)
		qlogger.info('OBJECT="%s" FILENAME="%s" Parsing Completed.',self.OBJECT_TYPE, file_name)

		if load_next_batch :
			self._batch += 1
			if not self.preserve_api_output:
				qlogger.debug("Removing tmp file " + file_name)
				try:
					os.remove(file_name)
				except OSError:
					pass
			else:
				qlogger.debug("Not removing tmp file " + file_name)
			qlogger.info("Found truncation warning, auto loading next batch from last webapp id: %s" % self.lastId)
			response['next_batch_params'] = None
			return response
		else:
			qlogger.debug("Done with parsing, returning.")
			return response
			
	@property
	def api_end_point(self):
		return "/qps/rest/3.0/search/was/webapp"
	# end of api_end_point

	def getIds(self):
		return self.ids
	# end of getIds

	def run(self):
		super(webAppIdFetcher, self).run()
		# self.appIdQueue.put(self.getIdParams())
	# end of run

	def getIdParams(self, idList=None):
		if idList is not None:
			ids = idList
		else:
			ids = self.ids

		id_min = min(ids) - 1
		id_max = max(ids) + 1

		params = "<ServiceRequest>"
		params += "<preferences><verbose>true</verbose></preferences>"
		params += "<filters>"
		params += ("<Criteria field=\"id\" operator=\"GREATER\">%s</Criteria>") % id_min
		params += ("<Criteria field=\"id\" operator=\"LESSER\">%s</Criteria>") % id_max
		params += "</filters>"
		params += "</ServiceRequest>"

		return params
	# end of getIdParams

	def _process_root_element(self, elem):
		if elem.tag == self.ROOT_TAG:
			for id_elem in list(elem):
				if id_elem.tag == self.ID_TAG:
					#qlogger.debug("Processed id %s" % id_elem.text)
					# qualysModule.splunkpopulator.utils.printStreamEventXML("_internal", "Processed id %s" % id_elem.text )
					self.ids.append(id_elem.text)
					# self.appIdQueue.put(id_elem.text)
		else:
			pass
		#end if
	#end _process_root_element
# end of class webAppIdFetcher
