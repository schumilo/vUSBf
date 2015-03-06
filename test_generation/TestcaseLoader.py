"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

from Testcase import Testcase

class testcase_loader():
    def __init__(self, object_file):
        filehandler = open(object_file, 'r')
        self.payloads = []
        for line in filehandler:
            line = line.replace("+---------------------------------------------------------+", "")
            line = line.replace("REPRODUCE_KEY:", "")
            line = line.replace("\n", "")
            if line != "":
                _tmp = Testcase(0)
                _tmp.load_bas64_strings(line)
                self.payloads.append(_tmp)

        print "[*] " + str(len(self.payloads)) + " testcase in file \"" + object_file + "\""

    def get_number_of_elements(self):
        return len(self.payloads)

    def get_data_chunk(self, number_of_elements):
        if len(self.payloads) == 0:
            return None
        _tmp = self.payloads[:number_of_elements]
        self.payloads = self.payloads[number_of_elements:]
        return _tmp