"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

import os.path, sys, time, random

from emulator import emulator

sys.path.append(os.path.abspath('../'))
from usbparser import *
from fileParser import *
from descFuzzer import *


class enumeration(emulator):
    def __init__(self, fuzzer):
        super(enumeration, self).__init__(fuzzer)
        self.descriptor = self.fuzzer.get_descriptor()
        #print self.descriptor
        self.string_descriptor = self.fuzzer.get_string_descriptor()

    def __get_complete_configuration_descriptor(self, configuration_num):
        configuration = get_configuration_descriptor(self.descriptor, configuration_num)
        if configuration == None:
            return None

        extra_payload = configuration[0]
        for ifDesc in configuration[1]:
            extra_payload = extra_payload / ifDesc[0]
            for e in ifDesc[1]:
                extra_payload = extra_payload / e
        return extra_payload

    def _calc_response(self, data):
        scapy_data = usbredir_parser(data).getScapyPacket()
        packet_length = 0
        extra_payload = None

        # check if data comes from control endpoint
        if scapy_data.Htype != 100:
            return None

        # check if data comes from endpoint 0 (output)
        if scapy_data.endpoint != 0x80:
            return scapy_data

        descriptor_request = scapy_data.value >> (8)
        descriptor_num = scapy_data.value % 256
        request = scapy_data.request

        # device descriptor
        if descriptor_request == 0x01:
            extra_payload = self.descriptor[0]
            packet_length = len(str(extra_payload))

        # configuration descriptor
        elif descriptor_request == 0x02:
            if scapy_data.length <= 9:
                configuration = get_configuration_descriptor(self.descriptor, descriptor_num)
                if configuration == None:
                    extra_payload == None
                else:
                    packet_length = scapy_data.length
                    extra_payload = configuration[0]
            else:
                extra_payload = self.__get_complete_configuration_descriptor(descriptor_num)
                packet_length = len(str(extra_payload))

        # string descriptor
        elif descriptor_request == 0x03:
            if descriptor_num < len(self.string_descriptor) + 1:
                extra_payload = self.string_descriptor[descriptor_num - 1]
            else:
                extra_payload = usb_string_descriptor('\x04\x03\x09\04')
            packet_length = len(str(extra_payload))
            #extra_payload.show()

        # redir stuff
        scapy_data.HLength = 10 + len(str(extra_payload))
        scapy_data.status = 0
        scapy_data.length = packet_length


        if extra_payload is None:
            scapy_data.HLength = 10
            return scapy_data

        return (scapy_data / extra_payload)
