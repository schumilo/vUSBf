import os.path, sys, time, random

from enumeration import enumeration

lib_path = os.path.abspath('../')
sys.path.append(lib_path)


class abortion_enumeration(enumeration):

	max_number_of_packets = 13

	def __init__(self, fuzzer):	
		super(abortion_enumeration, self).__init__(fuzzer)
		self.count = 0 

	def _calc_response(self, data):
		if self.count == self.max_number_of_packets:
			return ""
		else:
			self.count += 1
			return super(abortion_enumeration, self)._calc_response(data)

