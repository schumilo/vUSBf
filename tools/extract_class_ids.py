"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

import sys

start = "# List of known"
end = "# List of Audio Class Terminal Types"
start_flag = False

vid = ""
count = -1

f = open(sys.argv[1])

try:
    for line in f:
        if not start_flag:
            if line.startswith(start):
                start_flag = True
        else:
            if line.startswith(end):
                sys.exit(0)
            elif line.startswith("C "):
                print line.split(" ")[1]
            else:
                pass
finally:
    f.close()
