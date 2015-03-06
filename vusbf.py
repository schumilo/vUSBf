#!/usr/bin/python
"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

# suppress scapy ipv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys
import os
import config
from process.only_payload import only_payload_process
from process.multi_process import multi_processing
from process.distributor_process import server
from process.client_process import client
from process.execute_object import execute_object_process

__author__ = 'Sergej Schumilo'
__version__ = '0.2'

splash = "         _        _                  _               _     \n"
splash += " __   __(_) _ __ | |_  _   _   __ _ | |  _   _  ___ | |__  \n"
splash += " \ \ / /| || '__|| __|| | | | / _` || | | | | |/ __|| '_ \ \n"
splash += "  \ V / | || |   | |_ | |_| || (_| || | | |_| |\__ \| |_) |\n"
splash += "   \_/  |_||_|    \__| \__,_| \__,_||_|  \__,_||___/|_.__/ \n"
splash += "                                   \n"
splash += "   / _| _   _  ____ ____ ___  _ __ \n"
splash += "  | |_ | | | ||_  /|_  // _ \| '__|\n"
splash += "  |  _|| |_| | / /  / /|  __/| |   \n"
splash += "  |_|   \__,_|/___|/___|\___||_|   \n"

splash = "        _      __              __   __  _______ ____ \n"
splash += " _   __(_)____/ /___  ______ _/ /  / / / / ___// __ )\n"
splash += "| | / / / ___/ __/ / / / __ `/ /  / / / /\__ \/ __  |\n"
splash += "| |/ / / /  / /_/ /_/ / /_/ / /  / /_/ /___/ / /_/ / \n"
splash += "|_______/   \__/\__,_/\__,_/_/   \____//____/_____/  \n"
splash += "   / __/_  __________  ___  _____ \n"
splash += "  / /_/ / / /_  /_  / / _ \/ ___/ \n"
splash += " / __/ /_/ / / /_/ /_/  __/ /   \n"
splash += "/_/  \__,_/ /___/___/\___/_/ \n"


# parameter prefix and number of following options
# type, number of parameters, list_of_recommend_parameter, list_of_illegal_parameter
parameter = [['o', 1, [], []],
             ['e', 1, [], []],
             ['ef', 1, ['e'], []],
             ['tf', 1, ['e'], []],
             ['cf', 1, ['e'], []],
             ['n', 1, ['e'], ['nr']],
             ['nr', 1, ['e'], ['n']],
             ['sp', 2, ['e'], ['rm', 's', 'sc', 'c', 'w']],
             ['w', 0, ['e'], ['n'], ['rm', 's', 'sp', 'sc', 'c']],
             ['eon', 3, [], ['rm', 's', 'sc', 'c', 'w']],
             ['eo', 1, ['o'], ['rm', 's', 'sc', 'c', 'w']],
             ['r', 0, ['o', 'e'], ['rm', 'sp', 's', 'sc', 'c', 'w']],
             ['rm', 0, ['o', 'e', 'p'], ['sp', 's', 'sc', 'c', 'w']],
             ['s', 2, ['e'], ['rm', 'sp', 'r', 'sc', 'c', 'w']],
             ['sc', 2, ['o', 'p', 'e'], ['rm', 'sp', 'r', 's', 'c', 'n', 'nr', 'w']],
             ['c', 2, ['o', 'p'], ['rm', 'sp', 'r', 's', 'sc', 'n', 'nr', 'w']],
             ['C', 0, ['e'], []],
             ['p', 1, [], []],
             ['v1', 0, [], ['v2']],
             ['v2', 0, [], ['v1']],
             ['L', 0, [], []],
             ['h', 0, [], []],
             ['K', 0, [], []],
             ['sh', 0, [], []],
             ['l', 0, [], []],
             ['rl', 0, [], []]]


def parameter_parser(parameter_list):
    exec_path = "test_generation/execution.xml"
    testcase_path = "test_generation/testcase.xml"
    test_path = "test_generation/test.xml"

    reload_test = False
    shuffle_test = True

    if '-ef' in [e[0] for e in parameter_list]:
        exec_path = [e[1] for e in parameter_list if e[0] == '-ef'][0]

    if '-cf' in [e[0] for e in parameter_list]:
        testcase_path = [e[1] for e in parameter_list if e[0] == '-cf'][0]

    if '-tf' in [e[0] for e in parameter_list]:
        test_path = [e[1] for e in parameter_list if e[0] == '-tf'][0]

    if '-rl' in [e[0] for e in parameter_list]:
        reload_test = True

    # if '-rl' in [e[0] for e in parameter_list]:
    # shuffle_test = True

    parameter_type = [e[0] for e in parameter_list]

    # def execute_object_process(host, port, object_file):

    if '-eon' in parameter_type:
        print "EXECUTE OBJECT MODE (NETWORK)"
        host = [e[1] for e in parameter_list if e[0] == '-eon'][0]
        port = int([e[2] for e in parameter_list if e[0] == '-eon'][0])
        object_file = [e[3] for e in parameter_list if e[0] == '-eon'][0]
        execute_object_process("" + object_file, host=host, port=port)

    if '-eo' in parameter_type:
        print "EXECUTE OBJECT MODE"
        object_file = [e[1] for e in parameter_list if e[0] == '-eo'][0]
        target_object = [e[1] for e in parameter_list if e[0] == '-o'][0]
        if '-v1' in [e[0] for e in parameter_list]:
            config.PRINT_DEVICE_DESCRIPTORS = True
        if '-v2' in [e[0] for e in parameter_list]:
            config.VERBOSE_LEVEL = 5

        execute_object_process("" + object_file, target=target_object)

    if '-sp' in parameter_type:
        print "ONLY PAYLOAD MODE"
        host = [e[1] for e in parameter_list if e[0] == '-sp'][0]
        port = int([e[2] for e in parameter_list if e[0] == '-sp'][0])
        exec_name = [e[1] for e in parameter_list if e[0] == '-e'][0]
        exec_list = []
        for e in [e[1] for e in parameter_list if e[0] == '-n']:
            exec_list.append(int(e))

        only_payload_process(host, port, exec_name, exec_list, exec_path, testcase_path, test_path)

    elif '-r' in parameter_type:
        print "SINGLE CORE MODE"

        target_object = [e[1] for e in parameter_list if e[0] == '-o'][0]

        exec_name = [e[1] for e in parameter_list if e[0] == '-e'][0]
        exec_list = []
        for e in [e[1] for e in parameter_list if e[0] == '-n']:
            exec_list.append(int(e))

        multi_processing(1, target_object, exec_name, exec_list, exec_path, testcase_path, test_path,
                         reload_test, shuffle_test)

    elif '-rm' in parameter_type:
        print "MULTIPROCESSING MODE"

        process_number = int([e[1] for e in parameter_list if e[0] == '-p'][0])
        target_object = [e[1] for e in parameter_list if e[0] == '-o'][0]

        exec_name = [e[1] for e in parameter_list if e[0] == '-e'][0]
        exec_list = []
        for e in [e[1] for e in parameter_list if e[0] == '-n']:
            exec_list.append(int(e))

        multi_processing(process_number, target_object, exec_name, exec_list, exec_path, testcase_path, test_path,
                         reload_test, shuffle_test)

    elif '-s' in parameter_type:
        print "SERVER MODE"
        # target_object = [e[1] for e in parameter_list if e[0] == '-o'][0]

        host = [e[1] for e in parameter_list if e[0] == '-s'][0]
        port = int([e[2] for e in parameter_list if e[0] == '-s'][0])
        exec_name = [e[1] for e in parameter_list if e[0] == '-e'][0]
        exec_list = []
        for e in [e[1] for e in parameter_list if e[0] == '-n']:
            exec_list.append(int(e))

        server(host, port, exec_name, exec_list, exec_path, testcase_path, test_path, shuffle_test)

    elif '-sc' in parameter_type:
        print "HYBRID NOT IMPLEMENTED YET - SORRY :)"

    elif '-c' in parameter_type:
        print "CLIENT MODE"
        target_object = [e[1] for e in parameter_list if e[0] == '-o'][0]

        process_number = int([e[1] for e in parameter_list if e[0] == '-p'][0])
        host = [e[1] for e in parameter_list if e[0] == '-c'][0]
        port = int([e[2] for e in parameter_list if e[0] == '-c'][0])

        client(process_number, target_object, host, port, reload_test)

    # TODO FIX ME
    elif '-l' in parameter_type:
        print "List payloads:\n"
        payload_file = os.listdir("payload/")
        for payload in payload_file:
            if payload.endswith(".obj"):
                print "=> " + payload
                if os.path.isfile("payload/" + payload.split(".obj")[0] + ".info"):
                    print "\t====INFO================================"
                    f = open("payload/" + payload.split(".obj")[0] + ".info")
                    for line in f:
                        print "\t" + line.replace("\n", "")
                    f.close()
                else:
                    print "\t====INFO================================"
                    print "\t no info"
                print "\t========================================"

    elif '-L' in parameter_type:
        print "List emulators:\n"
        emulators = os.listdir("emulator/")
        for emulator in emulators:
            if emulator.endswith(".py") and emulator != "__init__.py" and emulator != "emulator.py":
                print "=> " + emulator.split(".py")[0]


def check_parameter(parameter_list):
    for a in parameter_list:
        data = [e for e in parameter if e[0] == a[0][1:]][0]

        # illegal
        for element in parameter_list:
            if element[0][1:] in data[3]:
                # print element
                print "Illegal parameter: -" + element
                return False

        # recommend
        for element in data[2]:
            if element not in [e[0][1:] for e in parameter_list]:
                print "Parameter not found: -" + element
                return False

    return True


def main():
    global splash
    print splash
    print "A KVM/QEMU based USB-fuzzing framework."
    print __author__ + ", OpenSource Training Spenneberg 2015"
    print "Version: " + __version__
    print ""
    print "Type -h for help"
    if len(sys.argv[1:]) == 0:
        return

    parameter_list = argv_parser()
    if parameter_list is None:
        return

    if check_parameter(parameter_list):
        parameter_parser(parameter_list)
    else:
        return


def print_help():
    f = open("help.txt")
    for line in f:
        print line,


def argv_parser():
    data = sys.argv[1:]
    if '-h' in data:
        print_help()
        return None
    else:

        parameter_list = []
        i = 0
        parameter_element = []
        for element in data:
            if i == 0:
                if element.replace("-", "") in [e[0] for e in parameter]:
                    if len(parameter_element) != 0:
                        parameter_list.append(parameter_element)
                        parameter_element = []
                    i = [e[1] for e in parameter if e[0] == element.replace("-", "")][0]
                    parameter_element.append(element)
                else:
                    raise Exception("illegal parameter error")
            else:
                parameter_element.append(element)
                i -= 1
        if parameter_element is not None:
            if parameter_element not in parameter_list:
                value = [e[1] for e in parameter if e[0] == parameter_element[0][1:]][0]
                if len(parameter_element) != value + 1:
                    raise Exception("illegal parameter error")
                parameter_list.append(parameter_element)
        return parameter_list


if __name__ == "__main__":
    main()
