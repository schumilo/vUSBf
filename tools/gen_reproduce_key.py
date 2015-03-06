"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

import sys
#sys.path.append(os.path.abspath('../'))
#from test_generation.Testcase import Testcase, Fuzzing_instruction

if len(sys.argv) != 2:
    print "Usage: python " + sys.argv[0] + " <logfile_file>"
    sys.exit(1)


filehandler = open(sys.argv[1], 'r')
lock = True
for line in filehandler:
    if not lock and not line.startswith("+--------------------------"):
        print line

    if line.startswith("+--------------------------"):
        if not lock:
            lock = True
        else:
            lock = False
