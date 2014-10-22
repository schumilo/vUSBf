from usbEmulator import usb_emulator
import pickle
from fuzz_configuration.xml_parser import xml_parser

import time

import random

def only_payload_process(host, port, exec_name, exec_list, exec_path, testcase_path, test_path):
    path_prefix = ""
    print testcase_path
  #  data = []
    data = xml_parser(path_prefix + test_path, path_prefix + testcase_path, path_prefix + exec_path).calc_tests(exec_name)

  #  if exec_list != []:
  #      print "NEW"
  #      new_data = []
  #      for e in exec_list:
  #          new_data.append(data[e])
  #      data = new_data
  #      
  #  file_pi = open('mal_payload.obj', 'w')
  #  pickle.dump(data, file_pi)

#    filehandler = open('mal_payload2.obj', 'r')
#    data = pickle.load(filehandler)

#    random.shuffle(data)
    emu = usb_emulator([host, port], 0, 0)
    print "Number of tests: " + str(len(data))
    for e in data:
        print e
        #if e[0] == 7841715 or e[0] == 6056107:
        time.sleep(0.2)
        e[2].print_data()
        print "TEST #" + str(e[0])
#               e[2].print_data()
        emu.setup_payload(e)
        emu.fire(1, 1, "")
        #if e[0] == 5006486:
        #        break

