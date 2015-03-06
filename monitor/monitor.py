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
import config


class monitor(object):
    def __init__(self, qemu, filename):
        if qemu == None:
            raise Exception("qemu null pointer")
        self.qemu = qemu
        if filename == None:
            raise Exception("filename null pointer")
        self.filename = filename

    def log_reload(self):
        if self.filename != "":
            f = open(self.filename, "a")
            f.write(config.MESSAGE_VM_RELOAD)
            f.close()

    def monitor(self, title):
        pass
