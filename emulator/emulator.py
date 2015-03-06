"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

import config

class emulator(object):

    def __init__(self, fuzzer):
        if fuzzer == None:
            raise Exception("fuzzer object null pointer")
        # TODO type check fuzzer object
        self.fuzzer = fuzzer

    # fuzz data and return data as string
    def _fuzz_data(self, scapy_data):
        if scapy_data == None:
            return ""
        else:
            return self.fuzzer.post_fuzzing(scapy_data)

    def get_response(self, data):
        response = self._calc_response(data)
        response = self._fuzz_data(response)
        if config.PRINT_DEVICE_DESCRIPTORS:
            print config.DELIMITER
            response.show()

        return response

    def _calc_response(self, data):
        pass
