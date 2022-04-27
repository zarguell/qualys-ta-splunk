import json
import six.moves.urllib.request as urlreq, six.moves.urllib.parse as urlpars, six.moves.urllib.error as urlerr
import csv
import re, os

from qualysModule import qlogger
from qualysModule.splunkpopulator.basepopulator import BasePopulator
import qualysModule.splunkpopulator.utils
from lib.splunklib.modularinput import Event
from io import open

class ActivityLogPopulatorConfiguration:
    _params_not_allowed = ["since_datetime", "until_datetime", "action", "output_format"]

    def __init__(self, logger):
        self.logger = logger
        self.api_filters = {}
        self.batch = 1
        self.truncation_limit = 1000
        
    def add_api_filter(self, name, value, user_defined=False):
        if not user_defined or name not in self._params_not_allowed:
            qlogger.info("Adding Activity Log API parameter %s with value %s", name, value)
            self.api_filters[name] = value
        else:
            qlogger.warning("Parameter %s with value %s was specified, but it is not allowed by TA. Not adding to API call.", name,value)


class ActivityLogPopulator(BasePopulator):
    OBJECT_TYPE = "Activity Log"
    FILE_PREFIX = "activity_log"
    SOURCE = 'qualys'
    SOURCETYPE = 'qualys:activityLog'
    HOST = 'localhost'
    INDEX = 'main'

    def __init__(self, configuration, event_writer):
        super(ActivityLogPopulator, self).__init__(configuration.logger)
        self.LOGGED = 0
        self._api_filters = configuration.api_filters
        self.truncation_limit = configuration.truncation_limit
        self._batch = configuration.batch
        self.HOST = configuration.host
        self.INDEX = configuration.index
        self.EVENT_WRITER = event_writer

    @property
    def get_logged_events(self):
        return self.LOGGED
     
    @property
    def get_api_parameters(self):
        return dict(
            list({
                "action": "list",
                "output_format": "csv",
                'truncation_limit': self.truncation_limit
            }.items()) + list(self._api_filters.items())
        )
        
    @property
    def api_end_point(self):
        return "/api/2.0/fo/activity_log/"

    def _process_root_element(self, elem):
        logged = 0
        for responseJson in elem["data"]:
            event = Event(host=self.HOST, index=self.INDEX, source=self.SOURCE,
                          sourcetype=self.SOURCETYPE)
            event.data = json.dumps(responseJson)
            self.EVENT_WRITER.write_event(event)
            self.LOGGED = self.LOGGED + 1
            logged += 1
        return logged
        
    def _parse(self, file_name):
        qlogger.info('OBJECT="%s" FILENAME="%s" Parsing Started.', self.OBJECT_TYPE, file_name)
        logged = 0
        total = 0
        response = {'error': False}
        load_next_batch = False
        next_url = None

        self._pre_parse()
        try:
            data = {'data': []}
            warning = {}
            with open(file_name, "rt") as f:
                # increasing the current maximum field size allowed by the parser by 10 times.
                csv.field_size_limit(1000000)
                reader = csv.DictReader(f)
                for line in f:
                    for row in reader:
                        if not (re.search(r'----(.*)', str(row)) or
                                re.search(r'(WARNING)|(\b.*next batch.*\b)', str(row))):
                            data["data"].append(row)
                        elif re.search(r'(\b.*action=list*\b)', str(row)):
                            warning.update(row)
                        else:
                            break;
            if warning:
                for k, v in list(warning.items()):
                    if re.search(r'(\b.*action=list*\b)', str(v)):
                        load_next_batch = True
                        next_url = str(v)
                        response['next_batch_params'] = next_url

            total = len(data["data"])
            logged = self._process_root_element(data)

        except Exception as e:
            qlogger.error("Failed to parse API Output for endpoint %s. Message: %s", self.api_end_point, e.message)

        self._post_parse()

        qlogger.info("Parsed %d %s entry. Logged=%d", total, self.OBJECT_TYPE, logged)
        qlogger.info('OBJECT="%s" FILENAME="%s" Parsing Completed.', self.OBJECT_TYPE, file_name)

        if load_next_batch and next_url is not None:
            self._batch += 1
            if not self.preserve_api_output:
                self.remove_file(file_name)
            else:
                qlogger.debug("Setting mandates to preserve API output. Not removing tmp file %s", file_name)
            qlogger.info("Found truncation warning, auto loading next batch from url:%s" % next_url)
            next_batch_params = qualysModule.splunkpopulator.utils.get_params_from_url(next_url)
            response['next_batch_params'] = next_batch_params
            return response
        else:
            qlogger.debug("Done with parsing, returning.")
            return response

    def remove_file(self, file_name):
        qlogger.debug("Removing tmp file %s", file_name)
        try:
            os.remove(file_name)
        except OSError as e:
            qlogger.warning("Could not remove tmp file %s. Error: %s", file_name, e.message)