# -*- coding: utf-8 -*-
__author__ = "Bharat Patel"
__copyright__ = "Copyright (C) 2014, Bharat Patel"
__license__ = "New BSD"
__version__ = "1.0"

import sys
import abc
from threading import current_thread
from qualysModule.splunkpopulator.utils import QualysAPIClient, bool_value
from qualysModule import *
import qualysModule
from qualysModule.lib import api
import splunk.clilib.cli_common as scc

import qualysModule.lib.api as qapi
import qualysModule.splunkpopulator.utils
import time
from datetime import datetime
import six.moves.http_client as httplib
import six
from io import open
from six.moves import range

from defusedxml import ElementTree as ET

import lxml.etree as LET

class BasePopulatorException(Exception):
    pass


class BasePopulator(six.with_metaclass(abc.ABCMeta)):
    # Set proper values in child classes
    #
    OBJECT_TYPE = "Unknown"
    FILE_PREFIX = "unknown"
    ROOT_TAG = 'NONE'

    def __init__(self, logging_handler=None):

        """

        :rtype : BasePopulator
        """
        assert isinstance(qapi.client, qualysModule.lib.api.Client.APIClient)

        self.api_client = qapi.client

        if logging_handler is None:
            logger = logging.getLogger('BASE')
            console_log_handler = logging.StreamHandler(sys.stdout)
            logger.addHandler(console_log_handler)
            formatter = logging.Formatter('%(message)s')
            console_log_handler.setFormatter(formatter)
            self._logger = logger
        else:
            self._logger = logging_handler

        self._logger.setLevel(logging.INFO)
        self._batch = 1
        self._logged = 0
        self._parsed = 0
        self.qualysConf = scc.getMergedConf("qualys")
        self.preserve_api_output = bool_value(self.qualysConf['setupentity'].get('preserve_api_output', False))
        self.propsConf = scc.getMergedConf("props")
        try:
            self.hd_event_truncate_limit = int(self.propsConf['qualys:hostDetection'].get('TRUNCATE'))
            self.hd_event_truncate_source = "App"
        except:
            self.hd_event_truncate_limit = int(self.propsConf['default'].get('TRUNCATE'))
            self.hd_event_truncate_source = "Global"

    @abc.abstractmethod
    def run(self):
        return

    @property
    @abc.abstractmethod
    def api_end_point(self):
        return

    def run(self):
        self._logged = 0
        self._parsed = 0
        next_batch_params = None
        while True:
            response = self.__fetch_and_parse(next_batch_params)
            try:
                next_batch_params = response['next_batch_params']
            except:
                break
        return response

    @property
    def get_api_parameters(self):
        return {"action": "list", "details": "Basic"}

    def __fetch(self, params=None):

        if self.api_end_point:
            api_params = self.get_api_parameters
            if params is not None:
                WASApi = self.api_client.isPortalEndpoint(self.api_end_point)
                if WASApi:
                    api_params = params
                else:
                    api_params = dict(list(api_params.items()) + list(params.items()))
            # For host_detection calls, use the ID range in the filename, otherwise use the time
            if "host_detection" in self.FILE_PREFIX and 'ids' in api_params:
                filename = temp_directory + "/%s_%s_Process-%s_%s_batch_%s.xml" % (
                    self.FILE_PREFIX, api_params['ids'], os.getpid(), current_thread().getName(),
                    self._batch)
            elif "policy_posture" in self.FILE_PREFIX and 'policy_id' in api_params:
                filename = temp_directory + "/%s_Process-%s_%s_PolicyId_%s_batch_%s.xml" % (
                    self.FILE_PREFIX, os.getpid(), current_thread().getName(), str(api_params.get("policy_id")),
                    self._batch)
            else:
                filename = temp_directory + "/%s_%s_%s_%s_batch_%s.xml" % (
                    self.FILE_PREFIX, start_time.strftime('%Y-%m-%d-%H-%M-%S'), current_thread().getName(), os.getpid(),
                    self._batch)
            response = self.api_client.get(self.api_end_point, api_params, api.Client.XMLFileBufferedResponse(filename))
            return response
        else:
            raise Exception("API endpoint not set, when fetching values for Object type:%", self.OBJECT_TYPE)

    def __fetch_and_parse(self, params=None):
        while True:
            try:
                response = self.__fetch(params)

                response_status = False
                response_status = response.get_response()
                if response_status != True:
                    qlogger.error("Error during Fetching, Cleaning up and retrying")
                    try:
                        os.rename(response.file_name,response.file_name + ".errored")
                        time.sleep(3)
                        continue
                    except OSError:
                        pass
                # else:
                # break
                # endif

                qlogger.info("%s fetched", self.OBJECT_TYPE)

                if self.OBJECT_TYPE == "detection":
                    qlogger.info("HD event truncate limit = %d and source = %s", self.hd_event_truncate_limit, self.hd_event_truncate_source)

                parseresponse = self._parse(response.file_name)

                if 'next_batch_params' in parseresponse:
                    return parseresponse
                if parseresponse:
                    if 'retry' in parseresponse and parseresponse['retry']:
                        qlogger.info("Cleaning up and retrying after 3 seconds...")
                        try:
                            os.remove(response.file_name)
                        except:
                            pass
                        time.sleep(3)
                        continue
                    if "Internal Error" in parseresponse or "Internal error" in parseresponse:
                        if "host_detection" in self.FILE_PREFIX:
                            # When Internal Error exceptions are returned, api_params wont be defined
                            # Make sure this is caught, and revert to saving to another filename
                            try:
                                filename = temp_directory + "/%s_%s_Process-%s_%s_batch_%s_errored.xml" % (
                                    self.FILE_PREFIX, params['ids'], os.getpid(), current_thread().getName(),
                                    self._batch)
                            except Exception as e:
                                filename = temp_directory + "/%s_%s_%s_%s_batch_%s_errored.xml" % (
                                    self.FILE_PREFIX, start_time.strftime('%Y-%m-%d-%H-%M-%S'), current_thread().getName(),
                                    os.getpid(), self._batch)
                                pass
                        else:
                            filename = temp_directory + "/%s_%s_%s_%s_batch_%s_errored.xml" % (
                                self.FILE_PREFIX, start_time.strftime('%Y-%m-%d-%H-%M-%S'), current_thread().getName(),
                                os.getpid(), self._batch)
                        qlogger.error("API Internal Error, Leaving File [%s], and Retrying", filename)
                        try:
                            os.rename(response.file_name, filename)
                        except OSError:
                            pass
                        continue
                    elif "not well-formed" in parseresponse:
                        if "host_detection" in self.FILE_PREFIX:
                            try:
                                filename = temp_directory + "/%s_%s_Process-%s_%s_batch_%s_errored.xml" % (
                                    self.FILE_PREFIX, params['ids'], os.getpid(), current_thread().getName(),
                                    self._batch)
                            except Exception as e:
                                filename = temp_directory + "/%s_%s_%s_%s_batch_%s_errored.xml" % (
                                    self.FILE_PREFIX, start_time.strftime('%Y-%m-%d-%H-%M-%S'), current_thread().getName(),
                                    os.getpid(), self._batch)
                                pass
                        else:
                            filename = temp_directory + "/%s_%s_%s_%s_batch_%s_errored.xml" % (
                                self.FILE_PREFIX, start_time.strftime('%Y-%m-%d-%H-%M-%S'), current_thread().getName(),
                                os.getpid(), self._batch)
                        qlogger.error("Malformed XML detected [%s], and Retrying", filename)
                        try:
                            os.rename(response.file_name, filename)
                        except OSError:
                            pass
                        continue
                    else:
                        break
                else:
                    break
            # except Exception, e:
            # qlogger.exception("Unknown Exception occurred in basepopulator.")
            # return False
            except Exception as e:
                import traceback
                qlogger.debug("Exception while parsing. %s :: %s", str(e), traceback.format_exc())
                if 'operation timed out' in six.text_type(e):
                    # qlogger.error("Unable to save data to file %s", self.file_name)
                    qlogger.error("Timeout while fetching, Retrying %s", e)
                else:
                    raise BasePopulatorException("could not load API response. Reason: %s" % str(e))
        # endwhile

        if not self.preserve_api_output:
            qlogger.debug("Removing tmp file " + response.file_name)
            try:
                os.remove(response.file_name)
            except OSError:
                pass
            return response
        else:
            qlogger.debug("Not removing tmp file " + response.file_name)
            return response

    # end

    def chunk_id_set(id_set, num_threads):
        '''
		This method chunks given id set into sub-id-sets of given size
		'''
        for i in range(0, len(id_set), num_threads):
            yield id_set[i:i + num_threads]

    # end of for loop

    # end of chunk_id_set

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
                            # Send to ET.ParseError instead of raising to BasePopulatorException so we can return and retry
                            raise ET.ParseError("API Error - Found Internal Error. Clean up and Retry")
                    elem.clear()
                elif elem.tag == self.ROOT_TAG:
                    total += 1
                    if self._process_root_element(elem):
                        logged += 1
                    elem.clear()

                elif elem.tag == "WARNING":
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

    """
    This method will be called whenever we found self.ROOT_TAG element
    Return boolean True if we end up creating a log entry for this  element else return false
    """

    @abc.abstractmethod
    def _process_root_element(self, elem):
        """


        :param elem:
        :rtype : bool
        """
        pass

    """
    Implement any post parsing logic you want here, this method will be called after each batch, before next batch is fetched,
    good place to log any breadcrumbs
    """

    def _post_parse(self):
        pass

    """
    Anything to be done before parsing the XML
    """

    def _pre_parse(self):
        pass

    @staticmethod
    def get_log_line_from_tuple(tuple_obj, prefix=""):
        to_log = []
        if prefix:
            to_log.append(prefix)
        for attr in tuple_obj._fields:
            to_log.append('%s %s=%r' % (prefix, attr, tuple_obj.__getattribute__(attr)))
        return " ".join(to_log)

    def output(self, log, *args, **kwargs):
        self._logger.info(log, *args, **kwargs)

    @staticmethod
    def convert_zulu_date(zulu_string):
        pass

    def remove_glossary_tag(self, file_name):
        new_file_name = file_name + '_copy'
        with open(new_file_name, 'wb') as f:
            with open(file_name) as fp:
                skip = False
                for line in fp.readlines():
                    if line.strip().lower() == '<glossary>':
                        f.write(line)
                        skip = True
                    if line.strip().lower() == '</glossary>':
                        skip = False
                    if not skip:
                        f.write(line)
        try:
            os.remove(file_name)
            os.rename(new_file_name, file_name)
            return file_name
        except Exception as e:
            qlogger.debug("Could not rename file name %s with %s; returning filename: %s", file_name, new_file_name,
                          new_file_name)
            return new_file_name