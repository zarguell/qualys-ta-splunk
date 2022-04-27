# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "Qualys, Inc."
__copyright__ = "Copyright (C) 2017, Qualys, Inc"
__license__ = "New BSD"
__version__ = "1.0"

import re, os, sys

# dynamically load all the .whl files
TA_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
WHL_DIR = TA_ROOT + "/bin/whl/"
for filename in os.listdir(WHL_DIR):
	if filename.endswith(".whl"):
		sys.path.insert(0, WHL_DIR + filename)

import six
import uuid
import six.moves.urllib.request as urlreq, six.moves.urllib.parse as urlpars, six.moves.urllib.error as urlerr
import base64
import zlib
import io
from datetime import datetime
import time
from io import open
from six.moves import range

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))
import lib.splunklib.client as client

try:
	import splunk.entity as entity
except:
	pass

import qualysModule
from qualysModule import *

from defusedxml import ElementTree as ET

from lxml import etree

class QualysAPIClientException(Exception):
	pass
# End of QualysAPIClientException class

class QualysAPIClient:
	"""
	Deprecated: see qualysModule.lib.api.Client
	"""
	READ_CHUNK_SIZE = 256 * 10240  # read this many bytes at a time when writing to file\
	USE_PROXY = False
	PROXY_HOST = None

	def __init__(self, api_server, api_user, api_password, enable_debug=False):
		self.api_server = api_server
		self.api_user = api_user
		self.api_password = api_password
		self.debug = enable_debug
		if not api_server:
			raise QualysAPIClientException("Invalid Qualys Server URL specified.")
		if not api_user or not api_password:
			raise QualysAPIClientException("Please set valid credentials.")
		if not self._validate_credentials:
			raise QualysAPIClientException("Failed to validate credentials.")

	@property
	def _validate_credentials(self):

		ret = False
		try:			
			response = self.get('/msp/about.php')
			if self.debug:
				qlogger.info(response)
			if response:
				if response['error']:
					qlogger.info("Error occurred trying to validate credentials. Error: CODE=%s, Message=%s",
								 response['error_code'], response['error_message'])
				elif response['status'] == 401:
					qlogger.info("Invalid credentials provided. Please check your username and password.")
				elif response['status'] == 200:
					try:
						root = ET.fromstring(response['body'])
						if root.find('WEB-VERSION') is not None:
							ret = True
					except ET.ParseError as e:
						qlogger.error("Failed to parse. XML=%s", response['body'])
						ret = False
		except QualysAPIClientException as e:
			pass

		return ret


	def get(self, end_point, params=None, write_to_file=False, file_name=None):
		request = None
		"""
		:param end_point:
		:param params:
		:param write_to_file:
		:param file_name:
		:return:
		"""
		if params is None:
			params = {}
		if write_to_file and (not file_name or file_name is None):
			file_name = '/tmp/' + str(uuid.uuid4()) + '.xml'

		response_object = {'status': False, 'savedAsFile': write_to_file,
						   'response': None, 'fileName': None, 'error': False, 'error_message': 'None', 'error_code': 0}

		auth = 'Basic ' + base64.urlsafe_b64encode("%s:%s" % (self.api_user, self.api_password))
		headers = {'User-Agent': "QualysSplunkPopulator:PythonPackage",
				   'X-Requested-With': "QualysSplunkPopulator",
				   'Authorization': auth}
		url = self.api_server + end_point
		data = urlpars.urlencode(params)
		if QualysAPIClient.USE_PROXY and QualysAPIClient.PROXY_HOST:
			qlogger.info("Using proxy=%s", QualysAPIClient.PROXY_HOST)
			proxy = urlreq.ProxyHandler({'https': QualysAPIClient.PROXY_HOST})
			opener = urlreq.build_opener(proxy)
			urlreq.install_opener(opener)

		req = urlreq.Request(url, data, headers)
		try:
			qlogger.info("Calling API:%s, with Parameters:%s", url, data)
			request = urlreq.urlopen(req)
			response_object['status'] = request.getcode()
			if response_object['status'] != 200:
				response_object['body'] = request.read()
			if write_to_file:
				try:

					firstChunk = True
					with open(file_name, 'wb') as fp:
						while True:
							chunk = request.read(QualysAPIClient.READ_CHUNK_SIZE)

							if firstChunk:
								firstChunk = True
								if chunk.startswith("<!--"):
									# discard the first line, it's probably a leading warning
									(discard, chunk) = chunk.split("\n", 1)
									# end if
							# end if

							if not chunk: break
							fp.write(chunk)
						response_object['fileName'] = file_name

				except IOError as e:
					qlogger.exception("Unable to save API response as FILE:%s", file_name)
					response_object['error'] = True
					response_object['savedAsFile'] = False
				else:
					response_object['savedAsFile'] = True
			else:
				response_object['body'] = request.read()
			qlogger.info("API call:%s was successful. File saved: %s", url, file_name)
		except urlerr.URLError as ue:
			response_object['error'] = True
			response_object['error_message'] = ue.reason
			if ue.code:
				response_object['error_code'] = ue.code
			else:
				response_object['error_code'] = -1
		except TypeError as te:
			# qlogger.exception(te)
			response_object['error'] = True
			response_object['error_message'] = str(te)
		finally:
			try:
				request.close()
			except NameError:
				pass

		return response_object
# End of QualysAPIClient class

def get_params_from_url(url):
	return dict(urlpars.parse_qsl(urlpars.urlparse(url).query))
# End of get_params_from_url method

def getCredentials(session_key):
	myapp = 'TA-QualysCloudPlatform'
	realm = 'TA-QualysCloudPlatform-Api'
	try:
		entities = entity.getEntities(['admin', 'passwords'], namespace=myapp, owner='nobody', sessionKey=session_key, count=-1)
	except Exception as e:
		qlogger.error("Could not get %s credentials from Splunk. Cannot continue. Error: %s", myapp, str(e))
		raise Exception("Could not get %s credentials from Splunk. Error: %s" % (myapp, str(e)))

	for i, c in list(entities.items()):
		if c['eai:acl']['app'] == myapp and c['realm'] == realm:
			qlogger.info("%s using username %s and its associated password." % (c['eai:acl']['app'], c['username']))
			return c['username'], c['clear_password']

	qlogger.error("No credentials found. Cannot continue.")
	raise Exception("No credentials found.")
# End of getCredentials method

def bool_value(string_val):
	true_values = ["yes", "y", "true", "1"]
	false_values = ["no", "n", "false", "0", ""]

	if isinstance(string_val, six.string_types):
		if string_val.lower() in true_values:
			return True
		if string_val.lower() in false_values:
			return False

	return bool(string_val)
# End of bool_value method

def printStreamEventXML(index, message):
	if index is None:
		raise ValueError('index not provided.')
	# end of if
	if message is None:
		raise ValueError('message not provided.')
	# end of if

	print("<stream><event><index>{0}</index><data><![CDATA[{1}]]></data></event></stream>".format(index, message))
# End of printStreamEventXML method

def xml_iterator(filename):
	context = None
	try:
		context = iter(ET.iterparse(filename, events=('end',)))
	except ET.ParseError as e:
		if e.msg and 'invalid token' in str(e.msg):
			try:
				xmlstring = open(filename).read()
				for i in range(1,17):
					if i==12 : continue
					iso_iec = 'iso-8859-' + str(i)
					xmlstring = xmlstring.decode(iso_iec).encode('utf8')
				contentBuffer = io.BytesIO(xmlstring)
				context = iter(etree.iterparse(contentBuffer, events=('end',)))
				del xmlstring
			except Exception as err:
				raise ET.ParseError(err)
		else:
			raise ET.ParseError(e)
	except Exception as err:
		raise ET.ParseError(err)
	return context
# End of xml_iterator method

def timeStringToSeconds(timeString):
	numSeconds = None
	qlogger.info('time interval = %s' % timeString)
	pattern = '^(\d+w)?(\d+d)?(\d+h)?(\d+m)?(\d+s)?$'
	match = re.search(pattern, timeString)
	totalSeconds = 0
	if (match):
		for group in match.groups():
			if group == None:
				continue
			# if
			lastChar = group[-1:]
			inputValue = group.replace(lastChar, '')
			if lastChar == 'w':
				numSeconds = int(inputValue) * 7 * 24 * 60 * 60
			elif lastChar == 'd':
				numSeconds = int(inputValue) * 24 * 60 * 60
			elif lastChar == 'h':
				numSeconds = int(inputValue) * 60 * 60
			elif lastChar == 'm':
				numSeconds = int(inputValue) * 60
			elif lastChar == 's':
				numSeconds = int(inputValue)
			# if elif
			#print "num seconds = %d" % numSeconds
			totalSeconds = totalSeconds + numSeconds
		# for
	else:
		qlogger.info("ERROR: Time interval input %s is not valid.Using default time interval 1d." % timeString)
		totalSeconds = 86400
	# End of if-else on match

	if totalSeconds <= 0 :
		qlogger.info("INFO: Cannot wait for %d seconds before running again. Using default value 1d." % totalSeconds)
		totalSeconds = 86400
		#print "Result :: Total seconds = %d" % totalSeconds

	qlogger.info('time interval %s translates to %d seconds' % (timeString, totalSeconds));
	return totalSeconds
# End of of timeStringToSeconds method

def chunks(lst, numThreads):
	idsIndex = []
	intDivision = 0
	intMod = 0
    
	numIds = len(lst)

	if numThreads > 0:
		intDivision = int(numIds / numThreads)
		intMod = numIds % numThreads
    
	threadCnt = 0
	chunkLimit = 0
	while threadCnt < numThreads:
		if intMod > 0 and threadCnt < intMod:
			intSize = intDivision + 1
		else:
			intSize = intDivision
			
		yield lst[chunkLimit:chunkLimit+intSize]
		threadCnt += 1
		chunkLimit += intSize
# End of chunk method

class IDSet:
	"""
	Simple implementation of IDSet; makes a lot of assumptions

	"""

	def __init__(self):
		self.items = {}

	def addString(self, id_or_range):
		if id_or_range.count("-", 1) == 1:
			(left, right) = id_or_range.split("-", 1)
			self.items[int(left)] = int(right)
		else:
			self.items[int(id_or_range)] = int(id_or_range)
			# End of if

	def addRange(self, left, right):
		self.items[left] = right
	# End of addRange

	def count(self):
		id_count = 0
		for k in sorted(self.items):
			id_count = id_count + ((self.items[k] - k) + 1)
		#End of for
		return id_count
	#End of count

	def iterRanges(self):

		def theRanges():
			for k in sorted(self.items):
				yield k, self.items[k]
				#End of for
		#End of theRanges
		return theRanges()
	#End of iterRanges

	def split(self, max_size_of_list):
		# splits the current IDSet into multiple IDSets based on the max_size_of_list
		return IDSet.__split(list(self.iterRanges()), max_size_of_list)
	#End of split

	def tostring(self):
		out = []
		for k, v in self.iterRanges():
			if k == v:
				out.append(k)
			else:
				out.append("%d-%d" % (k, v))
		#end for
		return ",".join(map(str, out))
	#End of tostring

	@staticmethod
	def __split(ranges, max_size_of_list):
		lists = []
		counter = 0
		cur_list = IDSet()
		for k, v in ranges:
			t_size = v - k + 1
			if counter + t_size < max_size_of_list:
				counter += t_size
				cur_list.addRange(k, v)
			elif counter + t_size == max_size_of_list:
				cur_list.addRange(k, v)
				lists.append(cur_list)
				cur_list = IDSet()
				counter = 0
			else:
				room_left = max_size_of_list - counter
				cur_list.addRange(k, k + room_left - 1)
				lists.append(cur_list)

				# at this point, our remaining range is k+room_left to v, and that could be multiple ranges as well
				lists = lists + IDSet.__split([(k + room_left, v)], max_size_of_list)
				# get the last list
				cur_list_count = lists[-1].count()
				if cur_list_count < max_size_of_list:
					cur_list = lists.pop()
					counter = cur_list_count
				else:
					cur_list = IDSet()
					counter = 0
					#End of if
		#End of for

		if cur_list.count() > 0:
			lists.append(cur_list)
		#End of if

		return lists
		#end def
# End of IDSet class

"""
This mothod will convert the epoch dates to human readable format
"""
def convertTimeFormat(value):
	try	:
		if len(value) == 13:
			value = int(value)/1000
			return str(datetime.utcfromtimestamp(value).strftime('%Y-%m-%dT%H:%M:%SZ'))
		elif len(value) == 10:
			value = int(value)
			return str(datetime.utcfromtimestamp(value).strftime('%Y-%m-%dT%H:%M:%SZ'))
		else:
			value = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
			value = value.strftime('%Y-%m-%d %H:%M:%S')
			return str(int(time.mktime(datetime.strptime(value, "%Y-%m-%d %H:%M:%S").timetuple()) * 1000.0))
	except Exception as e:
		qlogger.error(str(e))
#End of convertTimeFormat method

"""
This mothod will check if the eval_datetime is greater than checkpoint_datetime
"""
def evalAfterCheckpoint(eval_datetime, checkpoint_datetime):
	qual_format = "%Y-%m-%dT%H:%M:%SZ"
	eval_dt = datetime.strptime(eval_datetime, qual_format)
	checkpoint_dt = datetime.strptime(checkpoint_datetime, qual_format)
	if eval_dt >= checkpoint_dt:
		return True
	else:
		return False
# End of evalAfterCheckpoint method

'''Get clear password'''
def get_password(session_key, username, realm):
	args = {'token': session_key, 'app': "TA-QualysCloudPlatform"}
	service = client.connect(**args)
	try:
		# Retrieve the password from the storage/passwords endpoint
		for storage_password in service.storage_passwords:
			if storage_password.username == username and storage_password.realm == realm:
				return storage_password.content.clear_password
	except Exception as e:
		raise Exception("An error occurred while decrypting credentials. Details: %s" % str(e))
# End of get_password method

'''Encripting the password'''
def encrypt_password(service, ca_pass, username, realm):
	try:
		# If the credential already exists, delete it.
		for storage_password in service.storage_passwords:
			if storage_password.username == username and storage_password.realm == realm:
				service.storage_passwords.delete(username, realm)
		# Create the credential.
		password = service.storage_passwords.create(ca_pass, username, realm)
		return password.encrypted_password
	except Exception as e:
		raise Exception("An error occurred while encrypting credentials. Details: %s" % str(e))
# End of encrypt_password method

#check if the instance is on Splunk Cloud
def is_cloud(server_info):
	try:
		instance_type = server_info.to_dict()['instance_type']
	except:
		instance_type = ''
	if instance_type in ['cloud', 'Cloud']:
		return True
	else:
		return False
# End of is_cloud method

"""Check if the instance is cloud and VM .seed file should be downloaded inside TA_APP"""
def get_seed_file_path(seed_file_path, cloud):
	_ta_tmp_path = "$SPLUNK_HOME/etc/apps/TA-QualysCloudPlatform/tmp"
	try:
		_splunk_home = os.environ['SPLUNK_HOME']
	except:
		_splunk_home = ''
	if _splunk_home in [None, '']:
		qlogger.error('$SPLUNK_HOME is not set on Splunk Cloud. Exiting...')
		exit(1)
	elif cloud and seed_file_path.startswith(_ta_tmp_path):
		return seed_file_path.replace("$SPLUNK_HOME", _splunk_home)
	else:
		qlogger.error(
				"You are on Splunk Cloud. "
				"Directory path for VM Detection .seed file should be inside $SPLUNK_HOME/etc/apps/TA-QualysCloudPlatform/tmp dicrtory. "
				"PATH GIVEN: %s. "
				"Exiting...", seed_file_path)
		exit(1)
#End of get_seed_file_path method

"""Convert string True & False to boolean values"""
def str2bool(value):
	BOOLEAN_TRUE = ['1', 'True', True, 1, "yes"]
	BOOLEAN_FALSE = ['0', 'False', False, 0, "no", ""]
	if value in BOOLEAN_TRUE:
		return True
	elif value in BOOLEAN_FALSE:
		return False
	else:
		raise ValueError("Cannot covert {} to a bool".format(value))

def is_valid_data_input_startDate(startDateStr, dataInputName):
	try:
		fimDataInputs = ["fim_events","fim_incidents","fim_ignored_events"]

		if dataInputName in fimDataInputs:
			dataInputStartDate = "2017-01-01T00:00:00.000Z"
			startDate = datetime.strptime(startDateStr, '%Y-%m-%dT%H:%M:%S.%fZ')
			dataInputValidDate = datetime.strptime(dataInputStartDate, '%Y-%m-%dT%H:%M:%S.%fZ')
		elif dataInputName == "sem_detection":
			dataInputStartDate = "2021-01-26T00:00:00Z"
			startDate = datetime.strptime(startDateStr, '%Y-%m-%dT%H:%M:%SZ')
			dataInputValidDate = datetime.strptime(dataInputStartDate, '%Y-%m-%dT%H:%M:%SZ')
		else:
			dataInputStartDate = "1999-01-01T00:00:00Z"
			startDate = datetime.strptime(startDateStr, '%Y-%m-%dT%H:%M:%SZ')
			dataInputValidDate = datetime.strptime(dataInputStartDate, '%Y-%m-%dT%H:%M:%SZ')
        
		if startDate < dataInputValidDate:
			raise Exception("Invalid Start Date for "+dataInputName+" data input. Please enter date equal or greater than "+dataInputStartDate+".")
		elif dataInputName in fimDataInputs and startDateStr != startDate.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+"Z":
			raise Exception("Invalid Start Date for "+dataInputName+" data input. Please enter date equal or greater than "+dataInputStartDate+".")
		elif dataInputName not in fimDataInputs and startDateStr != startDate.strftime('%Y-%m-%dT%H:%M:%SZ'):
			raise Exception("Invalid Start Date for "+dataInputName+" data input. Please enter date equal or greater than "+dataInputStartDate+".")
		else:
			return True
	except ValueError as e:
		if hasattr(e, 'message'):
			excMessage = e.message
		else:
			excMessage = e
		raise Exception(excMessage)
	except Exception as ex:
		if hasattr(ex, 'message'):
			excMessage = ex.message
		else:
			excMessage = ex
		raise Exception(excMessage)
