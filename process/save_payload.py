from usbEmulator import usb_emulator
import pickle
from fuzz_configuration.xml_parser import xml_parser

import time

import random

def save_payload_process( exec_name, exec_list, exec_path, testcase_path, test_path):
    path_prefix = ""
    print testcase_path
  #  data = []
    data = xml_parser(path_prefix + test_path, path_prefix + testcase_path, path_prefix + exec_path).calc_tests(exec_name)

    if exec_list != []:
        print "NEW"
        new_data = []
        for e in exec_list:
            new_data.append(data[e])
        data = new_data
    else:
	print "No specification of payload!"
        
    file_pi = open('payload/mal_payload.obj', 'w')
    pickle.dump(data, file_pi)

    print "Write payload to payload/mal_payload.obj file..."

