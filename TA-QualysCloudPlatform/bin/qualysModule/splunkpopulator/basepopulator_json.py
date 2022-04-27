# -*- coding: utf-8 -*-
__author__ = "Qualys, Inc"
__copyright__ = "Copyright (C) 2018, Qualys, Inc"
__license__ = "New BSD"
__version__ = "1.0"

import sys
import abc
from threading import current_thread
from qualysModule.splunkpopulator.utils import QualysAPIClient, bool_value
from qualysModule import *
import qualysModule
from qualysModule.lib import api

import qualysModule.lib.api as qapi
import qualysModule.splunkpopulator.utils
import time
from datetime import datetime
import json
import six.moves.http_client as httplib
import splunk.clilib.cli_common as scc
import six
from io import open


class BasePopulatorJsonException(Exception):
    pass


class BasePopulatorJson(six.with_metaclass(abc.ABCMeta)):
    # Set proper values in child classes
    #
    OBJECT_TYPE = "Unknown"
    FILE_PREFIX = "unknown"
    ROOT_TAG = 'NONE'
    IMAGEID = "Unknown"

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
        self._page = 1
        self._logged = 0
        self._parsed = 0
        self.next_batch_url = None
        self.qualysConf = scc.getMergedConf("qualys")
        self.preserve_api_output = bool_value(self.qualysConf['setupentity'].get('preserve_api_output', False))

    @abc.abstractmethod
    def run(self):
        return

    @property
    @abc.abstractmethod
    def api_end_point(self):
        return

    def saveCheckpoint(self):
        # dump contents of self.checkpointData into self.checkpoint
        try:
            json.dumps(self.checkpointData)
            with open(self.checkpoint, "w") as f:
                ckpt = json.dumps(self.checkpointData)
                if sys.version_info[0] < 3:
                    f.write(ckpt.decode('utf-8'))
                else:
                    f.write(ckpt)
        except (OSError, IOError):
            sys.stderr.write("Failed to write checkpoint in file %s" % self.checkpoint)

    def run(self):
        while True:
            response = self.__fetch_and_parse()
            try:
                self.next_batch_url = response['next_batch_url']
                if self.next_batch_url == True:
                    self._page += 1
                else:
                    break
            except:
                break
        return response

    @property
    def get_api_parameters(self):
        return {}

    def remove_file(self, file_name):
        if not self.preserve_api_output:
            qlogger.debug("Removing tmp file %s", file_name)
            try:
                os.remove(file_name)
            except OSError as e:
                qlogger.warning("Could not remove tmp file %s. Error: %s", file_name, str(e))
        else:
            qlogger.debug("Setting mandates to preserve API output. Not removing tmp file %s", file_name)

    def rename_file(self, old_filename, new_filename):
        try:
            os.rename(old_filename, new_filename)
        except OSError:
            qlogger.warning("Could not rename %s to %s. Leaving old file as it is.", old_filename, new_filename)

    def __fetch_and_parse(self):
        while True:
            try:
                response = self._fetch()

                if response.response_code == 204:
                    qlogger.warning("No contents matching given request.")
                    break

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

                qlogger.info("%s fetched", self.OBJECT_TYPE)
                parseresponse = self._parse(response.file_name)
                if 'next_batch_url' in parseresponse:
                    self.remove_file(response.file_name)
                    return parseresponse
                if parseresponse:
                    errored_file_name = "%s.%s" % (response.file_name, ".errored")
                    if "Internal Error" in parseresponse or "Internal error" in parseresponse:
                        qlogger.error(
                            "API Internal Error while fetching and parsing the API response. Leaving file %s and retrying.",
                            errored_file_name)
                        self.rename_file(response.file_name, errored_file_name)
                        continue
                    elif "not well-formed" in parseresponse:
                        qlogger.error("Malformed JSON detected. Leaving file %s and retrying.", errored_file_name)
                        self.rename_file(response.file_name, errored_file_name)
                        continue
                    elif "500" in parseresponse:
                        qlogger.error(
                            "500 Internal Server Error while fetching and parsing API response. Leaving %s and retrying",
                            errored_file_name)
                        self.rename_file(response.file_name, errored_file_name)
                        continue
                    else:
                        break
                else:
                    break
            except Exception as e:
                import traceback
                qlogger.debug("Exception while parsing. %s :: %s", str(e), traceback.format_exc())
                if 'operation timed out' in six.text_type(e):
                    qlogger.error("Timeout while fetching, Retrying %s", e)
                else:
                    import traceback
                    qlogger.error("Exception while parsing. %s :: %s", str(e), traceback.format_exc())
                    raise BasePopulatorJsonException("could not load API response. Reason: %s" % str(e))
        # endwhile

        self.remove_file(response.file_name)
        return response

    # End of  __fetch_and_parse

    def _fetch(self):
        api_params = {}
        api_end_point = self.api_end_point
        if api_end_point:
            filename = temp_directory + "/%s_%s_%s_%s_page_%s.json" % (
                self.FILE_PREFIX, start_time.strftime('%Y-%m-%d-%H-%M-%S'), current_thread().getName(), os.getpid(),
                self._page)
            response = self.api_client.get(api_end_point, api_params, api.Client.XMLFileBufferedResponse(filename))
            return response
        else:
            raise Exception("API endpoint not set, when fetching values for Object type:%", self.OBJECT_TYPE)

    # End of _fetch method

    """
    This method will be called to parse the json file.

    """

    def _parse(self, file_name):
        parseresponse = {'next_batch_url': True}
        qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Started', self.OBJECT_TYPE, file_name)
        self._pre_parse()
        try:
            self._process_json_file(file_name)
        except Exception as e:
            qlogger.error("Failed to parse JSON API Output for endpoint %s. Message: %s", self.api_end_point, str(e))
            return {}
        self._post_parse()
        qlogger.info('OBJECT="%s" FILENAME="%s" PARSING=Completed', self.OBJECT_TYPE, file_name)
        return parseresponse

    # End of _parse method

    """
    This method will be called whenever we found self.ROOT_TAG element
    Return boolean True if we end up creating a log entry for this  element else return false
    """

    @abc.abstractmethod
    def _process_json_file(self, file_name):
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
