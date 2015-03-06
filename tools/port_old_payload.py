"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

import sys
import os
sys.path.append(os.path.abspath('../'))
from test_generation.Testcase import Testcase, Fuzzing_instruction


class test_package:
    def __init__(self, raw_data, name_list, operation_list):
        if raw_data is None or name_list is None or operation_list is None:
            raise Exception("test error")
        self.raw_data = raw_data
        self.name_list = name_list
        self.operation_list = operation_list
        self.emulator = None

    def get_raw_data(self):
        return self.raw_data

    def get_name_list(self):
        return self.name_list

    def get_operation_list(self):
        return self.operation_list

    def print_data(self):
        print self.raw_data
        print "\t",
        print self.name_list
        print "\t",
        print self.operation_list

import pickle
if len(sys.argv) != 2:
    print "Usage: python " + sys.argv[0] + " <old_obj_file>"
    sys.exit(1)

filehandler = open(sys.argv[1], 'r')
data = pickle.load(filehandler)
j = 0
for e in data:
    j += 1
    _tmp = Testcase(j)
    i = 0
    for o in e[2].operation_list:
        _tmp.add_testcase(Fuzzing_instruction(e[2].raw_data[i], o[2], o[3]))
        # print str(o[2]) + " " + str(o[3]) + " " + str(e[2].raw_data[i])
        i += 1
    for o in e[1]:
        if o[0] == 'name':
            _tmp.add_option('emulator', o[1])
        if o[0] == 'descriptor':
            _tmp.add_option('descriptor', o[1])
    print "REPRODUCE_KEY:"
    print _tmp.encode_base64()
    print ""