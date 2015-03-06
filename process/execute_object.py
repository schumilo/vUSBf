"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

from usbEmulator import usb_emulator
from multi_process import multi_processing
from test_generation.TestcaseLoader import testcase_loader
import config
import os


def execute_object_process(object_file, host="", port=0, target=None):
    config.SERIAL_READ_RETRIES = config.SERIAL_READ_RETRIES_EXECUTE_MODE
    config.PROCESS_SLOW_START_THRESHOLD = config.PROCESS_SLOW_START_THRESHOLD_EXECUTE_MODE
    config.PROCESS_SLOW_START_THRESHOLD_FAIL_COUNTER = config.PROCESS_SLOW_START_THRESHOLD_FAIL_COUNTER_EXECUTE_MODE
    config.PROCESS_FAIL_REPAIR_COUNTER = config.PROCESS_FAIL_REPAIR_COUNTER_EXECUTE_MODE

    payloads = testcase_loader(object_file)
    if host == "" or port == 0:
        if target is not None:
            try:
                os.remove("log/vusbf_log_execute")
            except:
                pass
            multi_processing(1, target, "", "", "", "", "", False, None, payloads=payloads, file_name="execute")
            print "[*] Output:"
            print ""
            for line in open("log/vusbf_log_execute"):
                print line,
    else:
        for e in payloads.payloads:
            print e
            emu = usb_emulator([host, port], 0)
            emu.setup_payload(e)
            emu.execute()