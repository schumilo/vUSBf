"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

from usbEmulator import usb_emulator
from test_generation.XMLParser import xml_parser
import sys
import os
import time
sys.path.append(os.path.abspath('../'))
import config
import random

def only_payload_process(host, port, exec_name, exec_list, exec_path, testcase_path, test_path):

    path_prefix = "test_generation/"
    exec_path_value = path_prefix + "execution.xml"
    if exec_path != "":
        exec_path_value = exec_path

    testcase_path_value = path_prefix + "testcase.xml"
    if testcase_path != "":
        testcase_path_value = testcase_path

    test_path_value = path_prefix + "test.xml"
    if test_path != "":
        test_path_value = test_path

    xml_tree = xml_parser(test_path_value, testcase_path_value, exec_path_value)
    xml_tree.calc_tests(exec_name)

    print "[*] Number of tests: " + str(xml_tree.get_number_of_elements())
    xml_tree.print_tree()
    emu = usb_emulator([host, port], 0)
    payloads = xml_tree.get_data_chunk(config.NUMBER_OF_JOBS_PER_PROCESS_NM)
    random.shuffle(payloads)
    while payloads is not None:
        for e in payloads:
            print e
            emu.setup_payload(e)
            emu.execute()
            time.sleep(config.SLEEP_BETWEEN_TESTS)
        payloads = xml_tree.get_data_chunk(config.NUMBER_OF_JOBS_PER_PROCESS_NM)
    print "[*] Done..."