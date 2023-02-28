from __future__ import print_function

__author__ = 'mwirges'

from qualysModule.splunkpopulator.basepopulator import BasePopulator
from qualysModule.splunkpopulator.utils import IDSet
from qualysModule import qlogger

import six.moves.queue as Queue
import time
import qualysModule.splunkpopulator.utils
from six.moves import range

"""
It would be nice to decouple the apiclient and result parser a bit more, but
we'll follow convention for now.
"""


class HostIdRetriever(BasePopulator):
	truncation_limit = 5
	cp_last_run_datetime = '1999-01-01T00:00:00Z'
	host_api_filters={}
	global ars
	ars={}

	OBJECT_TYPE = "ids"
	FILE_PREFIX = "host_ids"
	ROOT_TAG = 'HOST_LIST'

	def __init__(self):

		super(HostIdRetriever, self).__init__()
		# Truncating the gathering of asset ids greatly increases the changes of something going wrong
		# Pull all Asset IDs at once, and we'll insert them in chunks after
		self.truncation_limit = 0
		self.host_api_filters={}

	# end __init__

	@property
	def get_api_parameters(self):
		return dict(list({"action": "list", "truncation_limit": self.truncation_limit, "vm_processed_after": self.cp_last_run_datetime}.items())+list(self.host_api_filters.items()))

	# end get_api_parameters

	@property
	def api_end_point(self):
		return "/api/2.0/fo/asset/host/"

	# end api_end_point

	def get_idset(self):
		return self.idset

	def chunk_id_set(self, id_set, num_threads):
		'''
		This method chunks given id set into sub-id-sets of given size
		'''
		for i in range(0, len(id_set), num_threads):
			yield id_set[i:i + num_threads]
		# end of for loop

	# end of chunk_id_set


	def _process_root_element(self, elem):
		global num_ids, chunks
		qualysModule.splunkpopulator.utils.printStreamEventXML("_internal", "Processing id set")
		ids = []
		ars={}
		count = 1
		if elem.tag == "HOST_LIST":
			for name in list(elem):
				if name.tag == "HOST" :
					value=[]
					for id in list(name) :
						if id.tag == 'ID' or id.tag == 'ID_RANGE':
							count += 1
							host_id=id.text
							ids.append(id.text)
						if id.tag =="ASSET_RISK_SCORE" :
							value.append("ARS="+id.text)
						if id.tag =="ASSET_CRITICALITY_SCORE" :
							value.append("ACS="+id.text)
						if id.tag == "ARS_FACTORS":
							vuln_count=[]
							for factors in list(id):
								if factors.tag == "ARS_FORMULA":
									value.append("ARS_FORMULA="+str(factors.text))
								if factors.tag == "VULN_COUNT" :
									vuln_count.append("ARS_FACTORS_VULN_COUNT_with_QDS_Severity_"+factors.attrib['qds_severity']+"="+factors.text)
								vuln_count_s=", ".join(vuln_count)
							value.append(vuln_count_s)
						value_s=", ".join(value)	
						ars[host_id]=value_s

		num_ids = len(ids)
		qlogger.debug("Inserting [%s] into queue", num_ids)

		#insert chunks of detection_truncation_limit ids as ID ranges into the queue
		#For subscriptions less than detection_truncation_limit assets, 1 range will be inserted with all assets
		#This can be configurable, and would mimic what truncation_limit for the asset/host call
		chunk_size = int(self.detection_truncation_limit) if int(self.detection_truncation_limit) > 0 else int(self.default_host_truncation_limit) 
		chunks = self.chunk_id_set(ids, chunk_size)
		for id_chunk in chunks:
			if id_chunk[0] == id_chunk[-1]:
				id_range = "%s" % (id_chunk[0])
			else:
				id_range = "%s-%s" % (id_chunk[0], id_chunk[-1])
			self._handle_idset(id_range)
		qlogger.debug("Sent %s list of ids to be handled", count)
		# print("Sent %s list of ids to be handled" % count)

	# end _process_root_element

	def _post_parse(self):
		return ars
		
	def _handle_idset(self, idset):
		qualysModule.splunkpopulator.utils.printStreamEventXML("_internal", "Got Host IDs : %s" % (idset.tostring()))