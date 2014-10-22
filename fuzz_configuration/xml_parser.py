import xml.etree.ElementTree as ET
import itertools
from fuzz_configuration.test import test_package


class xml_parser(object):

    def __init__(self, path_test, path_testcase, path_exec):
        self.test_root = self.__get_root(path_test)
        self.testcase_root = self.__get_root(path_testcase)
        self.exec_root = self.__get_root(path_exec)

    def __get_root(self, path):
	#print path
        try:
            return ET.parse(path).getroot()
        except:
            raise Exception("xml-file error (" + path + ")")

    def __action_operation_parser(self, node):
        test = {}
        test.update({"name": node.get('name')})

        count = 0
        raw_data = []
        for operation in node.findall('action'):
            operation_data = {}
            operation_data.update({"descriptor": operation.find('descriptor').get('name')})
            operation_data.update({"number": operation.find('descriptor').get('num')})
            operation_data.update({"type": operation.get('type')})

            # optional setup data
            optional_list = []
            for optional in operation.findall('field'):
                optional_data = {}
                # type cast
                if optional.get("type") == "int":
                    value = int(optional.get("value"))
                elif optional.get("type") == "hex":
                    value = int(optional.get("value"), 16)
                elif optional.get("type") == "string":
                    value = optional.get("value")
                else:
                    raise Exception("Unkown field type")

                optional_data.update({"Field": optional.get("name"), "Value": value})
                optional_list.append(optional_data)

            if len(optional_list) != 0:
                operation_data.update({"setup" + str(count): optional_list})

            test.update({"operation" + str(count): operation_data})
            raw_data.append([False, True])
            count += 1

        # unzip zip :-)
        test.update({"Raw": zip(*raw_data)})
        return test

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

        # return None
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
                value_list = self.__read_value_from_file(element.attrib["path"], element[0].attrib["delimiter"],
                                              int(element[0].text), element.attrib["type"])
            elif element.tag == "field":
                pass
            elif element.tag == "packet":
                pass
            else:
                raise Exception("Unknown tag \"" + str(element.tag) + "\"")

        return value_list


    def __fuzz_operation_parser(self, node):
        test = {}
        test.update({"name": node.get('name')})

        count = 0
        raw_data = []
        for operation in node.findall('fuzz'):
            operation_data = {}
            test.update({"operation-type": "fuzz"})
            operation_data.update({"packet": operation.find('packet').get('name')})
            operation_data.update({"field": operation.find('field').get('name')})
            test.update({"operation" + str(count): operation_data})
            raw_data.append(self.__value_parser(operation))
            count += 1

        # unzip zip :-)
        test.update({"Raw": zip(*raw_data)})
        return test

    def __get_test_parser(self, testname):
        data = {}
        node = self.test_root
        for element in node.findall('atomic_test'):
            if element.get('name') == testname:

                data.update({'name': element.get("name")})
                if element.get("type") == "fuzz":
                    return self.__fuzz_operation_parser(element)

                elif element.get("type") == "action":
                    return self.__action_operation_parser(element)

                else:
                    raise Exception("Unknown type")


    def __combine_tests(self, tests, combination_type):

        test_list = []

        if combination_type == "sequential":
            for test in tests:
                print test.get('name')
                name_list = []
                operation_list = []
                name_list.append(test.get('name'))


                for i in range(len(test.get('Raw')[0])):
                    descriptor = test.get('operation' + str(i)).get("descriptor")

                    if descriptor is None:
                        field = test.get('operation' + str(i)).get("field")
                        packet = test.get('operation' + str(i)).get("packet")
                        operation_list.append([0, "fuzz", field, packet])
                    else:
                        number = test.get('operation' + str(i)).get("number")
                        action_type = test.get('operation' + str(i)).get("type")
                        setup_list = []
                        j = 0
                        while True:
                            next_setup = test.get('operation' + str(i)).get("setup" + str(j))
                            j += 1
                            if next_setup == None:
                                break
                            setup_list.append(next_setup)
                        operation_list.append([0, "action", descriptor, action_type, number, setup_list])
                for data in test.get('Raw'):
                    print data
                    test_list.append(test_package(data, name_list, operation_list))

        elif combination_type == "parallel":
            operation_count = 0
            raw_data_list = []
            name_list = []
            operation_list = []
            name_count = 0
            for test in tests:
                name_list.append(test.get('name'))
                for i in range(len(test.get('Raw')[0])):

                    descriptor = test.get('operation' + str(i)).get("descriptor")

                    if descriptor == None:
                        field = test.get('operation' + str(i)).get("field")
                        packet = test.get('operation' + str(i)).get("packet")
                        operation_list.append([name_count, "fuzz", field, packet])
                    else:
                        number = test.get('operation' + str(i)).get("number")
                        action_type = test.get('operation' + str(i)).get("type")
                        setup_list = []
                        j = 0
                        while True:
                            next_setup = test.get('operation' + str(i)).get("setup" + str(j))
                            j += 1
                            if next_setup == None:
                                break
                            setup_list.append(next_setup)
                        operation_list.append([name_count, "action", descriptor, action_type, number, setup_list])
                    operation_count += 1
                name_count += 1

                raw_data_list.append(test.get('Raw'))

            new_raw_data_list = itertools.product(*raw_data_list)
            for e in new_raw_data_list:
                value = tuple()
                for i in range(len(e)):
                    for el in zip(e[i]):
                        value = value + el
                test_list.append(test_package(value, name_list, operation_list))

        return test_list

    def __testunit_parser(self, node, testcase_type):
        data_list = []

        for test in node:
            if test.tag == "testunit":
                data_list.append(self.__testunit_parser(test, test.attrib["type"]))
            elif test.tag == "test":
                data_list.append(self.__get_test_parser(test.get("name")))

        if testcase_type == "sequential":
            return self.__combine_tests(data_list, testcase_type)
        elif testcase_type == "parallel":
            return self.__combine_tests(data_list, testcase_type)
        else:
            raise Exception("Unknown testunit type")

    def __testcase_parser(self, node):
        for testunit in node:
            return self.__testunit_parser(testunit, testunit.get('type'))

    def __testcases_parser(self, testcase_name):
        node = self.testcase_root
        for testcase in node:
            if testcase.tag == "testcase":
                if testcase.get('name') == testcase_name:
                    return self.__testcase_parser(testcase)
            else:
                raise Exception("Unknown tag \"" + str(testcase.tag) + "\"")

    def __execution_parser(self, execution_name):
        node = self.exec_root
        data_list = []
        for execute in node:
            if execute.tag == "execute":
                #print execute.get('name')
                if execute.get('name') == execution_name:
                    data = []
                    for element in execute:
                        if element.tag == "testcase":
                            data_list = self.__testcases_parser(element.get('name'))
                        elif element.tag == "emulator":
                            if element.get("name") == "enumeration" or element.get("name") == "enumeration_abortion" or element.get("name") == "hid":
                                data.append(["name", element.get("name")])
                                data.append(["descriptor", element.get("descriptor")])
                                if element.get("reload-vm") == "yes":
                                    data.append(["reload", True])
                                else:
                                    data.append(["reload", False])
                                pass
                    break

        new_data_list = []
        if data_list == None:
            return None
        i = 0
        for element in data_list:
            new_data_list.append([i, data, element])
            i += 1

        return new_data_list


    def calc_tests(self, exec_name):
        return self.__execution_parser(exec_name)



#print len(xml_parser("test.xml", "testcase.xml", "execution.xml").calc_tests("ex1"))
#for e in xml_parser("test.xml", "testcase.xml", "execution.xml").calc_tests("ex1"):
#    print e
