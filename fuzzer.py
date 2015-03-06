"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""

from usbscapy import usb_string_descriptor

class fuzzer(object):
    def __init__(self, test):
        self.test = test
        self.string_descriptor = None

    def set_descriptor(self, descriptor):
        self.descriptor = descriptor

    def set_string_descriptor(self, string_descriptor):
        self.string_descriptor = string_descriptor

    def get_descriptor(self):
        return self.descriptor

    def get_string_descriptor(self):
        # if self.string_descriptor is None:
        min_d = usb_string_descriptor('\x04\x03\x09\01')
        max_d = usb_string_descriptor(
            '\xfe\x03\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P\x00P')
        format_string = usb_string_descriptor(
            '\xfe\x03%\x00\x00\x00%\x00\x01\x00%\x00\x02\x00%\x00\x03\x00%\x00\x04\x00%\x00\x05\x00%\x00\x06\x00%\x00\x07\x00%\x00\x08\x00%\x00\t\x00%\x00\n\x00%\x00\x0b\x00%\x00\x0c\x00%\x00\r\x00%\x00\x0e\x00%\x00\x0f\x00%\x00\x10\x00%\x00\x11\x00%\x00\x12\x00%\x00\x13\x00%\x00\x14\x00%\x00\x15\x00%\x00\x16\x00%\x00\x17\x00%\x00\x18\x00%\x00\x19\x00%\x00\x1a\x00%\x00\x1b\x00%\x00\x1c\x00%\x00\x1d\x00%\x00\x1e\x00%\x00\x1f\x00%\x00 \x00%\x00!\x00%\x00"\x00%\x00#\x00%\x00$\x00%\x00%\x00%\x00&\x00%\x00\'\x00%\x00(\x00%\x00)\x00%\x00*\x00%\x00+\x00%\x00,\x00%\x00-\x00%\x00.\x00%\x00/\x00%\x000\x00%\x001\x00%\x002\x00%\x003\x00%\x004\x00%\x005\x00%\x006\x00%\x007\x00%\x008\x00%\x009\x00%\x00:\x00%\x00;\x00%\x00<\x00%\x00=\x00%\x00>\x00')

        string_descriptor_list = []
        string_descriptor_list.append(min_d)
        string_descriptor_list.append(min_d)
        string_descriptor_list.append(format_string)
        return string_descriptor_list

    def post_fuzzing(self, scapy_data):

        # return scapy_data

        if self.test is None:
            raise Exception('Test is not set')

        test_elements = self.test.get_testcases()

        tmp = scapy_data
        i = 0

        while len(str(tmp)) != 0:
            try:
                for i in range(len(test_elements)):
                    if True:
                        if test_elements[i].get_packet_type() == "ALL":
                            try:
                                setattr(tmp, test_elements[i].get_field(), test_elements[i].get_value())
                            except:
                                pass
                        elif test_elements[i].get_packet_type().lower() == str(type(tmp)).split(".")[1].split("'")[0]:
                            setattr(tmp, test_elements[i].get_field(), test_elements[i].get_value())

                i += 1
            except:
                pass
            tmp = tmp.payload
        return scapy_data