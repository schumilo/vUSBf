"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

import os.path, sys

from enumeration import enumeration

lib_path = os.path.abspath('../')
sys.path.append(lib_path)


class abortion_enumeration(enumeration):
    max_number_of_packets = 13

    def __init__(self, fuzzer):
        super(abortion_enumeration, self).__init__(fuzzer)
        self.count = 0

    def _calc_response(self, data):
        if self.count == self.max_number_of_packets:
            return ""
        else:
            self.count += 1
            return super(abortion_enumeration, self)._calc_response(data)

