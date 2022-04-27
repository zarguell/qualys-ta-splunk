# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "Qualys, Inc"
__version__ = "1.1"

import sys, os

TA_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

# dynamically load all the .whl files
WHL_DIR = TA_ROOT + "/bin/whl/"
for filename in os.listdir(WHL_DIR):
	if filename.endswith(".whl"):
		sys.path.append(WHL_DIR + filename)

'''Imports'''
from six.moves import input
import splunk.clilib.cli_common as scc  # used for getMergedConf() to get 'preserve_api_output' value
import qualysModule.splunkpopulator.utils  # for qualysModule.enableLogger()
from qualysModule.application_configuration import *  # for OptionParser()
import re

'''Declarations'''

TA_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
FILE_ROOT = TA_ROOT + "/tmp/"

'''Data Input Text Dictionary'''
DITD = {
    "pl" : "policy_",
    "po" : "policy_posture_Process-",
    "hid":"host_ids_",
    "hd":"host_detection_",
    "kb":"kb_",
    "wd":"was_detection_",
    "wid":"web_app_ids_",
    "csi":"cs_image_list_",
    "csv":"cs_image_vulns_list_",
    "csc":"cs_containers_list__",
    "cscv":"cs_container_vulns_",
    "fe": "fim_events_\w+_",
    "fi": "fim_incidents_\w+_",
    "fie": "fim_ignored_events_\w+_",
    "edr":"edr_events_",
    "edr_c":"edr_events_count_",
    "al":"activity_log_",
    "sem":"sem_detection_",
    "date_sec":"(?:\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}|\d+-\d+)",
    "date":"(?:\d{4}-\d{2}-\d{2}-\d{2}-\d{2}|\d+-\d+)",
    "pros":"?:Thread-\d+_|Thread-\d+_PolicyId_|MainThread_PID_|MainThread_|Process-|PID_|page_",
    "ext":".*\.xml|.*\.json"
}

'''To add new integration, one need to add the first 2 DITD, after that date, pros,ect are same.'''
rpc = r'^(?:'+DITD['po']+'|'+DITD['pl']+')('+DITD['date_sec']+'|'+DITD['date'] + '|(\d+))_('+DITD['pros']+')(\d+)('+ DITD['ext'] + ')'
rhd = r'^(?:'+DITD['hid']+'|'+DITD['hd']+')('+DITD['date_sec']+'|'+DITD['date'] +')_('+DITD['pros']+')(\d+)_('+ DITD['ext']  + ')'
rkb = r'^(?:'+DITD['kb']+')('+DITD['date_sec']+'|'+DITD['date'] +')_('+DITD['pros']+')(\d+)_('+ DITD['ext'] + ')'
rwas = r'^(?:'+DITD['wd']+'|'+DITD['wid']+')('+DITD['date_sec']+'|'+DITD['date'] +')_('+DITD['pros']+')(\d+)_.*\.xml'
redr = r'^(?:'+DITD['edr']+ '|' +DITD['edr_c']+')('+DITD['date_sec']+'|'+DITD['date'] +')_('+DITD['pros']+')(\d+)_('+ DITD['ext'] + ')'
rcs = r'^(?:'+DITD['csi']+'|'+DITD['csv']+'|'+DITD['csc']+'|'+DITD['cscv']+')('+DITD['date_sec']+'|'+DITD['date'] +')_('+DITD['pros']+')(\d+)_('+ DITD['ext'] + ')'
rfim = r'^(?:'+DITD['fe']+'|'+DITD['fi']+'|'+DITD['fie']+')('+DITD['date_sec']+'|'+DITD['date'] +')_('+DITD['pros']+')(\d+)_('+ DITD['ext'] + ')'
ral = r'^(?:'+DITD['al']+')('+DITD['date_sec']+'|'+DITD['date'] +')_('+DITD['pros']+')(\d+)_('+ DITD['ext']  + ')'
rsem = r'^(?:'+DITD['sem']+')('+DITD['date_sec']+'|'+DITD['date'] +')_('+DITD['pros']+')(\d+)_('+ DITD['ext']  + ')'

get_xml_count = False
get_json_count = False
get_all_count = False
yes = ('y', 'Y', 'yes', 'Yes', 'YES')
no = ('n', 'N', 'no', 'No', 'NO')

option_dicts = {
    'delete_pc_xml': 'Policy Compliance',
    'delete_hd_xml': 'Host Detection',
    'delete_kb_xml': 'Knowledge Base',
    'delete_wf_xml': 'Was Finding',
    'delete_al_xml': 'Activity Log',
    'delete_cs_json':'Container Security',
    'delete_edr_json': 'EDR Events',
    'delete_all': 'All files',
    'delete_fim_json':'File Integrity Monitoring',
    'delete_sem_xml': 'SEM'
}

qualys_conf = scc.getMergedConf("qualys")
preserve_api_output = qualys_conf['setupentity']['preserve_api_output']

'''get XML & JSON list'''

def get_file_list(reg_exp):
    return [x for x in os.listdir(FILE_ROOT) if re.match(reg_exp, x)]

'''XML & JSON List'''

PC_LIST = get_file_list(rpc)
PC_LIST = list(set(PC_LIST))

HD_LIST = get_file_list(rhd)
HD_LIST = list(set(HD_LIST))

KB_LIST = get_file_list(rkb)
KB_LIST = list(set(KB_LIST))

WAS_LIST = get_file_list(rwas)
WAS_LIST = list(set(WAS_LIST))

CS_LIST = get_file_list(rcs)
CS_LIST = list(set(CS_LIST))

EDR_LIST = get_file_list(redr)
EDR_LIST = list(set(EDR_LIST))

FIM_LIST = get_file_list(rfim)
FIM_LIST = list(set(FIM_LIST))

AL_LIST = get_file_list(ral)
AL_LIST = list(set(AL_LIST))

SEM_LIST = get_file_list(rsem)
SEM_LIST = list(set(SEM_LIST))

All_XML_COUNT = len(PC_LIST + HD_LIST + KB_LIST + WAS_LIST + AL_LIST + SEM_LIST)
All_JSON_COUNT = len(EDR_LIST + CS_LIST + FIM_LIST)
All_XML = PC_LIST + HD_LIST + KB_LIST + WAS_LIST + AL_LIST + SEM_LIST
All_JSON = EDR_LIST + CS_LIST + FIM_LIST

All_FILES = All_XML + All_JSON
All_FILES_COUNT = len(All_FILES)

'''Delete the selected files'''

def clean_file(pid, file):
    try:
        os.remove(str(FILE_ROOT) + str(file))
        qlogger.debug('Deleted: ' + str(file))
        return 1
    except IOError as e:
        qlogger.exception(e)
    return 0

'''Get specific files from the list and generate PID'''

def get_pid(data_input_name, file_list):
    reg_str = r'^((?:'+DITD['kb']+')|(?:'+DITD['po']+'|'+DITD['pl']+'|'+DITD['hid']+'|'+DITD['hd']+'|'+DITD['wd']+\
              '|'+DITD['wid']+'|'+DITD['csi']+'|'+DITD['csv']+'|'+DITD['edr_c']+'|'+DITD['edr']+\
              '|'+DITD['fe']+'|'+DITD['fi']+'|'+DITD['fie']+'|'+DITD['al']+'|'+DITD['sem']+'))('+DITD['date_sec']+'|' +DITD['date']\
              +'|(\d+))_('+DITD['pros']+')(\d+)('+ DITD['ext']+')'

    list_count = 0
    try:
        for file in file_list:
            file = os.path.basename(file)
            pid_tuple = re.search(reg_str, file)
            if not pid_tuple:
                pass
            else:
                pid = pid_tuple.groups()
                list_count += clean_file(pid[0], file)
        qlogger.info(data_input_name + ': Deleted ' + str(list_count) + ' file(s).')
    except IOError as e:
        qlogger.exception(e)


'''Check for the preserve_api_output'''

def check_option(option_name, file_list):
    option = False
    if preserve_api_output == 'False' or preserve_api_output == "0":
        option = True
    elif preserve_api_output == 'True' or preserve_api_output == "1":
        print('You have set the preserve_api_output to True. ' \
              'Do you want to delete the ' + option_name + ' files? y/n')
        choice = input().lower()
        qlogger.info('The choice made for deleting ' + option_name + ' files is %s', choice)
        if choice in yes:
            option = True
        elif choice in no:
            qlogger.info("Exiting the cleanup utility.")
            pass
        else:
            print("Please respond with 'yes' or 'no'")
    else:
        option = True

    if option:
        try:
            get_pid(option_name, file_list)
        except IOError as e:
            qlogger.exception(e)


'''__main__'''

def main():
    global get_xml_count, get_json_count, get_all_count

    parser = OptionParser()

    parser.add_option("--c", "--get-all-cnt", action="store_true", dest="get_all_count", default=False,
                      help="Get ALL files count")
    parser.add_option("--d", "--debug", action="store_true", dest="debug", default=False,
                      help="Debug mode")
    parser.add_option("--pc", "--d-pc-xml", action="store_true", dest="delete_pc_xml", default=False,
                      help="Delete XML specific to Policy Compliance Posture")
    parser.add_option("--hd", "--d-hd-xml", action="store_true", dest="delete_hd_xml", default=False,
                      help="Delete XML specific to Host Detection")
    parser.add_option("--kb", "--d-kb-xml", action="store_true", dest="delete_kb_xml", default=False,
                      help="Delete XML specific to Knowledge Base")
    parser.add_option("--was", "--d-was-xml", action="store_true", dest="delete_wf_xml", default=False,
                      help="Delete XML specific to WAS Findings")
    parser.add_option("--cs", "--d-cs-json", action="store_true", dest="delete_cs_json", default=False,
                      help="Delete JSON specific to Container Security")
    parser.add_option("--edr", "--d-edr-json", action="store_true", dest="delete_edr_json", default=False,
                      help="Delete JSON specific to EDR")
    parser.add_option("--fim", "--d-fim-json", action="store_true", dest="delete_fim_json", default=False,
                        help="Delete JSON specific to FIM.")
    parser.add_option("--all", "--d-all", action="store_true", dest="delete_all", default=False,
                      help="Delete All Files")
    parser.add_option("--al", "--d-al-xml", action="store_true", dest="delete_al_xml", default=False,
                      help="Delete XML specific to Activity Log")
    parser.add_option("--sem", "--d-sem-xml", action="store_true", dest="delete_sem_xml", default=False,
                      help="Delete XML specific to SEM")

    (options, args) = parser.parse_args()

    try:
        '''If options are true call the respective function and pass the list'''
        if options.debug:
            qualysModule.enableDebug(True)

        qualysModule.enableLogger()

        if options.delete_all:
            check_option(option_dicts['delete_all'], All_FILES)
            exit(0)

        if options.delete_pc_xml:
            if not PC_LIST:
                print("We didn't get any " + option_dicts['delete_pc_xml'] + " xml file to delete.")
            else:
                check_option(option_dicts['delete_pc_xml'], PC_LIST)

        if options.delete_hd_xml:
            if not HD_LIST:
                print("We didn't get any " + option_dicts['delete_hd_xml'] + " xml file to delete.")
            else:
                check_option(option_dicts['delete_hd_xml'], HD_LIST)

        if options.delete_kb_xml:
            if not KB_LIST:
                print("We didn't get any " + option_dicts['delete_kb_xml'] + " xml file to delete.")
            else:
                check_option(option_dicts['delete_kb_xml'], KB_LIST)

        if options.delete_wf_xml:
            if not WAS_LIST:
                print("We didn't get any " + option_dicts['delete_wf_xml'] + " xml file to delete.")
            else:
                check_option(option_dicts['delete_wf_xml'], WAS_LIST)
                
        if options.delete_cs_json:
            if not CS_LIST:
                print("We didn't get any " + option_dicts['delete_cs_json'] + " json file to delete.")
            else:
                check_option(option_dicts['delete_cs_json'], CS_LIST)

        if options.delete_edr_json:
            if not EDR_LIST:
                print("We didn't get any " + option_dicts['delete_edr_json'] + " json file to delete.")
            else:
                check_option(option_dicts['delete_edr_json'], EDR_LIST)

        if options.delete_fim_json:
            if not FIM_LIST:
                print("We didn't get any " + option_dicts['delete_fim_json'] + " json file to delete.")
            else:
                check_option(option_dicts['delete_fim_json'], FIM_LIST)

        if options.delete_al_xml:
            if not AL_LIST:
                print("We didn't get any " + option_dicts['delete_al_xml'] + " xml file to delete.")
            else:
                check_option(option_dicts['delete_al_xml'], AL_LIST)

        if options.delete_sem_xml:
            if not SEM_LIST:
                print("We didn't get any " + option_dicts['delete_sem_xml'] + " xml file to delete.")
            else:
                check_option(option_dicts['delete_sem_xml'], SEM_LIST)

        if options.get_all_count:
            get_all_count = True
        if get_all_count:
            if int(All_FILES_COUNT) < 1:
                print('There are ' + str(All_FILES_COUNT) + ' files in tmp folder.')
            else:
                print('There is/are total ' + str(All_FILES_COUNT) + ' file(s) in tmp folder. Out of which, ' + str(
                    All_JSON_COUNT) + ' is/are JSON and ' + str(All_XML_COUNT) + ' is/are XML file(s).')

    except IOError as e:
        qlogger.exception(e)
    exit(0)

'''The program starts here'''
if __name__ == "__main__":
    main()
