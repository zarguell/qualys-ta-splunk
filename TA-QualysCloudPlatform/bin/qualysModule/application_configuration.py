from six.moves.configparser import SafeConfigParser
from optparse import OptionParser
import sys
import os
from qualysModule import qlogger
import six
from io import open

APP_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '../'))
config_file = APP_ROOT + '/config/.qsprc'


class ApplicationConfiguration():
    BOOLEAN_TRUE = ['1', 'True', True, 1, "yes"]
    BOOLEAN_FALSE = ['0', 'False', False, 0, "no", ""]

    DEFAULT_SETTINGS = dict(api_server='https://qualysapi.qualys.com',
                            username='',
                            password='',
                            proxy=None,
                            log_output_directory='',
                            temp_directory='/tmp',
                            log_host_summary='True',
                            log_vuln_detections='True',
                            extra_host_summary='True',
                            minimum_qid='0',
                            truncation_limit='5000',
                            preserve_api_output='False',
                            host_summary_fields='ID,IP,TRACKING_METHOD,DNS,NETBIOS,OS,LAST_SCAN_DATETIME',
                            detection_fields='QID,TYPE,PORT,PROTOCOL,SSL,STATUS,LAST_UPDATE_DATETIME,LAST_FOUND_DATETIME,FIRST_FOUND_DATETIME,LAST_TEST_DATETIME',
                            log_host_details_in_detections='True',
                            detection_params='{"status":"New,Active,Fixed,Re-Opened"}',
                            first_run='True',
                            last_days=7,
                            use_multi_threading='False',
                            num_threads=2,
                            last_run_datetime=None)

    def __init__(self, settings_override=None, config_file_path=None, config_section_name='QUALYS',
                 default_settings=None):
        """
        Command line options will override settings from file, which overrides default settings
        :rtype : ApplicationConfiguration
        :param default_settings:
        :param load_from_file:
        :param parse_cli_options:
        :param config_file_path:
        """
        if config_file_path:
            self._config_file = config_file_path
        else:
            self._config_file = config_file

        self.load_from_file = True

        if isinstance(default_settings, dict):
            self.settings = default_settings
        else:
            self.settings = ApplicationConfiguration.DEFAULT_SETTINGS

        self.overrides = {}
        if isinstance(settings_override, dict):
            self.overrides = settings_override

        self.config_parser = SafeConfigParser()

        if config_section_name:
            self.config_section_name = config_section_name
        else:
            self.config_section_name = 'QUALYS'


    @property
    def config_file_path(self):
        return self._config_file

    @property
    def default_settings(self):
        return {}

    def load(self):

        if self.load_from_file:
            self._override_from_file()
        if not self.config_parser.has_section(self.config_section_name):
            self.config_parser.add_section(self.config_section_name)

    def _override_from_file(self):

        try:
            '''
            with open(self._config_file) as fp:
                self.config_parser.readfp(fp)
                if self.config_parser.has_section(self.config_section_name):
                    for setting in list(self.config_parser.items(self.config_section_name)):
                        name, value = list(setting)
                        self.settings[name] = value
            '''
        except IOError as e:
            qlogger.exception(e)
            pass

    def get_settings(self):
        return self.settings

    def get(self, name, default=None):
        if name in self.overrides:
            return self.overrides.get(name)
        else:
            return self.settings.get(name, default)


    def getBoolean(self, name, default):

        string_val = self.get(name, default)

        if isinstance(string_val, six.string_types):
            if string_val.lower() in ApplicationConfiguration.BOOLEAN_TRUE:
                return True
            if string_val.lower() in ApplicationConfiguration.BOOLEAN_FALSE:
                return False

        return bool(string_val)

    def set(self, name, value):
        self.config_parser.set(self.config_section_name, name, str(value))
        self.settings[name] = value

    def save_settings(self):
        """
        Write setting file to disk
        """
        with open(self._config_file, 'wb') as configfile:
            self.config_parser.write(configfile)

    @property
    def items(self):
        return list(self.settings.items())
