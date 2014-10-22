from usbscapy import * 
import sys

class report_desc_reader:
	

	def __init__(self, file):
		f = open(file)
		self.data = ""
		try:
			for line in f:
				self.data += line
		finally:
			f.close()


	def get_raw_data(self):
		data = self.data.replace("\n", "").replace(" ", "\\x")
		if data.endswith("\\x"):
			data = data[:-2]
		data = data.decode('string-escape')
		Raw(data).show()
		print len(data)
		return data


print report_desc_reader(sys.argv[1]).get_raw_data()
