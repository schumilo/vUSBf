from usbEmulator import usb_emulator
import pickle
from fuzz_configuration.xml_parser import xml_parser

import time
import random

def execute_object_process(host, port, object_file):
    filehandler = open(object_file, 'r')
    data = pickle.load(filehandler)
    emu = usb_emulator([host, port], 0, 0)
    counter = 0
    for e in data:
	counter += 1
	print "PAYLOAD #" + str(counter)
	e[2].print_data()
        emu.setup_payload(e)
        emu.fire(1, 1, "")
		
