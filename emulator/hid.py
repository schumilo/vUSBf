import os.path, sys, time, random

from emulator import emulator
from enumeration import enumeration

sys.path.append(os.path.abspath('../'))
from usbparser import *
from fileParser import *
from descFuzzer import *


class hid(enumeration):
    def __init__(self, fuzzer):
        super(hid, self).__init__(fuzzer)


    def __read_reports(self, reports_file):
        return "\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    def __read_report_descriptor(self, report_descriptor_file):
        raw_data = ""
        f = open(report_descriptor_file)
        try:
            for line in f:
                raw_data += line
        finally:
            f.close()

        raw_data = raw_data.replace("\n", "").replace(" ", "\\x")
        if raw_data.endswith("\\x"):
            raw_data = data[:-2]
        raw_data = raw_data.decode('string-escape')
        Raw(raw_data).show()
        return raw_data

    def _calc_response(self, data):

        scapy_data = usbredir_parser(data).getScapyPacket()
        packet_length = 0
        extra_payload = None

	try:
	    descriptor_request = scapy_data.value >> (8)
            descriptor_num = scapy_data.value % 256
            request = scapy_data.request

	    # report request
            if request == 1:
                report = ""
                for i in range(scapy_data.length):
                    report += chr(random.randint(0,255))
                scapy_data.HLength = 10 + scapy_data.length
                return (scapy_data / extra_payload)

            # report_descriptor request
            elif descriptor_request == 0x22:
                scapy_data.status = 0
                scapy_data.HLength = 10 + scapy_data.length
                extra_payload = self.report_desc
                return (scapy_data / extra_payload)

	    else:
		return super(hid, self)._calc_response(data)
	except:
	    return super(hid, self)._calc_response(data)
