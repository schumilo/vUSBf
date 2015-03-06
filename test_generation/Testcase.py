"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

import base64
import os
import sys
sys.path.append(os.path.abspath('../'))
import config

class Testcase(object):
    def __init__(self, ID):
        self.ID = ID
        self.list = []
        self.option = {}

    def S(*x):
        if len(x) == 1 and type(x[0]) == list:
            x = x[0]
        else:
            x = list(x)
        return ListSequence(x)

    def add_testcase(self, *testcase):
        # print type(testcase[0])
        if len(testcase) == 1 and type(testcase[0]) == list:
            self.list.append(testcase[0])
        else:
            self.list.extend(testcase)

    def print_message(self):
        message = "Test #" + str(self.ID) + ":\n"
        message += "+---------------------------------------------------------+\n"
        if config.PRINT_VERBOSE_TEST_INFO:
            for e in self.list:
                message += "\t" + e.gen_info_string() + "\n"
            message += str(self.option) + "\n"
        message += "REPRODUCE_KEY:\n" + self.encode_base64() + "\n"
        message += "+---------------------------------------------------------+\n"

        return message

    def encode_base64(self):
        message = str(self.ID) + "\n"
        message += "\n"
        for e in self.list:
            message += e.gen_info_string().replace("FT: ", "").replace("\t", " ").replace(":", "") + "\n"
        message += "\n"
        for k in self.option.keys():
            message += k
            message += " " + self.option[k] + "\n"
        return base64.b64encode(message.replace(" ", "\xff"))

    def decode_base64(self, data):
        return base64.b64decode(data).replace("\xff", " ")

    def load_bas64_strings(self, data):
        data = base64.b64decode(data).split("\n\n")
        try:
            self.ID = int(data[0], 10)
        except:
            self.ID = data[0]
        for e in data[1].split("\n"):
            _tmp = e.split("\xff")
            if len(_tmp) == 3:
                self.add_testcase(Fuzzing_instruction(int(_tmp[0],10), _tmp[1], _tmp[2]))
        for e in data[2].split("\n"):
            _tmp = e.split("\xff")
            if len(_tmp) == 2:
                self.add_option(_tmp[0], _tmp[1])

    def get_ID(self):
        return self.ID

    def get_number_of_testcases(self):
        return len(self.list)

    def get_testcase(self, num):
        try:
            return self.list[num]
        except:
            raise Exception("Bounds exception (num=" + str(num) + ")")

    def get_testcases(self):
        return self.list

    def add_option(self, key, value):
        self.option[str(key)] = str(value)

    def add_options(self, hm):
        self.option = hm

    def get_option(self, key):
        return self.option[key]

    def get_options(self):
        return self.option.keys()

    def __str__(self):
        return self.print_message()


class Instruction(object):
    def __init__(self):
        pass

    def gen_info_string(self):
        return "stub"


class Fuzzing_instruction(Testcase):
    def __init__(self, value, field, packet_type):
        self.value = value
        self.field = field
        self.packet_type = packet_type

    def gen_info_string(self):
        output = "FT: "
        try:
            output += self.value + "\t"
        except:
            output += str(self.value) + "\t"
        output += self.field + ": " + self.packet_type

        return output

    def get_value(self):
        return self.value

    def get_field(self):
        return self.field

    def get_packet_type(self):
        return self.packet_type

    def __str__(self):
        return self.gen_info_string()


if __name__ == "__main__":
    testcase = Testcase(33346)
    testcase.add_testcase(Fuzzing_instruction(1337, "A", "I"))
    testcase.add_testcase(Fuzzing_instruction("YO00", "B", "II"))
    testcase.add_testcase(Fuzzing_instruction(3317, "C", "III"))
    testcase.add_testcase(Fuzzing_instruction(12, "A", "I"), Fuzzing_instruction(21, "A", "I"))
    # print testcase.print_message()

    testcase.add_option(1, "Eins")
    testcase.add_option(2, "Zwei")
    testcase.add_option(3, "Drei")

    #print testcase.get_option(1)
    #print testcase.get_option(2)
    #print testcase.get_option(3)
    #print testcase.encode_base64()
    #print testcase.decode_base64(testcase.encode_base64())
    print testcase.print_message()
    t2 = Testcase(0)
    t2.load_bas64_strings(testcase.encode_base64())
    print t2
