"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

##
##	Chain		(a,b)(c,d) -> (a,c,b,d)
##	Product		(a,b)(c,d) -> (a,c)(a,d)(b,c)(b,d)
##	Linked		(a,b)(c,d) -> (a,c)(b,d)
##

import xml.etree.ElementTree as ET
from Sequence import *
from Testcase import *

EX_TAG = "execute"
EX_NAME = "name"

EX_TESTCASE_TAG = "testcase"
EX_TESTCASE_TAG_NAME = "name"

EX_OPTION_TAG = "option"
EX_OPTION_TAG_EMUL = "emulator"
EX_OPTION_TAG_DESC = "descriptor"
EX_OPTION_TAG_VMRL = "reload-vm"


TC_TAG = "testcase"
TC_NAME = "name"

TC_TU_TAG = "testunit"
TC_TU_TYPE = "type"
TC_TU_TYPE_P = "product"
TC_TU_TYPE_S = "chain"
TC_TU_TYPE_L = "linked"

TC_T_TAG = "test"
TC_T_NAME = "name"

class xml_parser(object):

	def __init__(self, path_test, path_testcase, path_exec):
		self.test_root = self.__get_root(path_test)
		self.testcase_root = self.__get_root(path_testcase)
		self.exec_root = self.__get_root(path_exec)
		self.data = None
		self.options = {}

	def get_descriptor():
		return "desc2.txt"

	def get_reload():
		return True
		
	def get_number_of_elements(self):
		if self.number_of_elements == None:
			raise Exception("Data error!")
		return self.number_of_elements
		
	def get_data_chunk(self, number_of_elements):
		if self.data == None:
			raise Exception("Data error!")
		return_data = []
		new_index = 0
		#print len(self.data)
		for e in self.data:
			self.index += 1
			tmp = Testcase(self.index)
			tmp.add_options(self.options)
			#print "ADD"
			if type(e) == list:
				for i in e:
					tmp.add_testcase(i)
			else:
				tmp.add_testcase(e)
			
			#tmp.add_testcase(e)
			return_data.append(tmp)
			new_index = new_index + 1
			if new_index >= number_of_elements:
				#print new_index
				break
		if len(return_data) == 0:
			return None
		return return_data
				
	
	def reset_data():
		calc_tests(self.default_exec_name)
		
	def print_tree(self):
		if self.tree != None:		
			print "+---------------------------------------------------+"
			self.__print_rec(self.tree, "")
			print "+---------------------------------------------------+"
			
	def __print_rec(self, list, tab_string):
		for e in list:
			if type(e) == dict:
				self.__print_rec(e, tab_string + "\t")
				next = []
				try:
					next.extend(e.get(TC_TU_TYPE_P))
				except:
					pass
				try:
					next.extend(e.get(TC_TU_TYPE_S))
				except:
					pass
				try:
					next.extend(e.get(TC_TU_TYPE_L))
				except:
					pass
				self.__print_rec(next, tab_string + "\t\t")
			else:
				print tab_string + e,
				tmp = self.build_list(e.replace("\t", ""))
				if tmp != None:
					print " [" + str(len(tmp)) + "]"
				else:
					print ""
	
	def __calc_rec(self, list, operator):
		data = []
		for e in list:
			if type(e) == dict:
				if e.get(TC_TU_TYPE_P) != None:
					data.append(self.__calc_rec(e.get(TC_TU_TYPE_P), TC_TU_TYPE_P))
				if e.get(TC_TU_TYPE_S) != None:
					data.append(self.__calc_rec(e.get(TC_TU_TYPE_S), TC_TU_TYPE_S))
				if e.get(TC_TU_TYPE_L) != None:
					data.append(self.__calc_rec(e.get(TC_TU_TYPE_L), TC_TU_TYPE_L))	
			else:
				data.append(e)
				
		final = S()
		if data == None:
			return None
		else:
			it = iter(data)
			first_element = it.next()
			if type(first_element) == str:
				final = self.build_list(first_element)
			else:
				final = first_element
			for e in it:
				if type(e) == str:
					if operator == TC_TU_TYPE_P:
						final *= self.build_list(e)
					if operator == TC_TU_TYPE_S:
						final += self.build_list(e)
					if operator == TC_TU_TYPE_L:
						final = final % self.build_list(e)
				else:
					if operator == TC_TU_TYPE_P:
						final *= e
					if operator == TC_TU_TYPE_S:
						final += e
					if operator == TC_TU_TYPE_L:
						final = final % e
				
		return final 
		
	def build_list(self, test_name):
		node = self.test_root
		for e in node:
			if test_name == e.attrib["name"] and e.attrib["type"] == "fuzz":
				for fuzz_block in e:
					a = None
					b = None
					c = None
					for values in fuzz_block:
						if values.tag == "packet":
							a = str(values.attrib["name"])
							#print a
						elif values.tag == "field":
							b = str(values.attrib["name"])
							#print b
						elif values.tag == "range" or values.tag == "file" or values.tag == "value":
							c = self.__value_parser(fuzz_block)
							#print c
						if (a != None) and (b != None) and (c != None):
							tmp = []
							for e in c:
								tmp.append(Fuzzing_instruction(e,b,a))
							tmp = S(tmp)
							return tmp

	def __read_value_from_file(self, file_name, delimiter, column, data_type):
		# TODO test if file exists
		data = []
		#f = open("fuzz_configuration/" + file_name)
		try:
			f = open(file_name)
		except:
			f = open("fuzz_configuration/" + file_name)

		try:
			for line in f:
				raw_data = line.replace("\n", "").split(delimiter)[column]
				if data_type == "int":
					data.append(int(raw_data))
				elif data_type == "hex":
					data.append(int(raw_data, 16))
				elif data_type == "string":
					data.append(raw_data)
				else:
					raise Exception("Unknown data type")
		finally:
			f.close()

		return data
			
	def __value_parser(self, node):
		packet_name = ""
		field_name = ""

		value_list = []
		for element in node:
			if element.tag == "range":
				a = int(element[0].text)
				b = int(element[1].text)
				if b - a <= 0:
			   		raise Exception("Range error")
				for i in range(b - a):
					value_list.append(i + a)
			elif element.tag == "value":
				value_list.append(int(element.text))
			elif element.tag == "file":
				value_list = self.__read_value_from_file(element.attrib["path"], element[0].attrib["delimiter"],int(element[0].text), element.attrib["type"])
			elif element.tag == "field":
				field_name = element.attrib['name']
			elif element.tag == "packet":
				packet_name = element.attrib['name']
			else:
		   		raise Exception("Unknown tag \"" + str(element.tag) + "\"")
		return value_list


	def __get_root(self, path):
		try:
			return ET.parse(path).getroot()
		except:
			raise Exception("XML Error: File not found (" + path + ")")
			
	def __testunit_parser(self, node, tab_str):
		final_list = []
		for e in node:
			if e.tag == TC_TU_TAG or e.tag == TC_T_TAG:
				if e.get(TC_TU_TYPE) == TC_TU_TYPE_P:
					final_list.append({TC_TU_TYPE_P: self.__testunit_parser(e, tab_str +"\t")})

				elif e.get(TC_TU_TYPE) == TC_TU_TYPE_S:
					final_list.append({TC_TU_TYPE_S: self.__testunit_parser(e, tab_str + "\t")})
				
				elif e.get(TC_TU_TYPE) == TC_TU_TYPE_L:
					final_list.append({TC_TU_TYPE_L: self.__testunit_parser(e, tab_str + "\t")})

				else:
					final_list.append(e.get("name"))
					
		return final_list


			
	def __testcase_parser(self, testcase_name):
		node = self.testcase_root
		for e in node:
			if e.tag == TC_TAG:
				if e.get(TC_NAME) == testcase_name:
					self.tree = self.__testunit_parser(e, "")
					self.data = self.__calc_rec(self.tree, "chain")
					self.number_of_elements = len(self.data)
					self.index = 0



	def __execution_parser(self, execution_name):
		node = self.exec_root
		data_list = []
		for execute in node:
			if execute.tag == EX_TAG:
				if execute.get(EX_NAME) == execution_name:
					data_list.append(execute)
		return data_list
		
	def __execution_parser_options(self, execution):
		node = execution
		for subelement in node:
			if subelement.tag == EX_TESTCASE_TAG:
				self.__testcase_parser(subelement.get(EX_TESTCASE_TAG_NAME))
			
			elif subelement.tag == EX_OPTION_TAG:
				self.options = subelement.attrib
				# NOT IMPLEMENTED :-)
				pass
				
		
	def calc_tests(self, exec_name):
		self.default_exec_name = exec_name
		execution = self.__execution_parser(exec_name)
		for e in execution:
			self.__execution_parser_options(e)

if __name__ == "__main__":
	xml_tree = xml_parser("test.xml", "testcase.xml", "execution.xml")
	xml_tree.calc_tests("ex2")
	xml_tree.print_tree()
	print xml_tree.get_number_of_elements()
	i = 0
	while True:
		a = xml_tree.get_data_chunk(1000)
		i += 1 
		print len(a)*i
		if a == None:
			break
		for e in a:
			print e
