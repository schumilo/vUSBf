
class test_package:
    def __init__(self, raw_data, name_list, operation_list):
        if raw_data is None or name_list is None or operation_list is None:
            raise Exception("test error")

        self.raw_data = raw_data
        self.name_list = name_list
        self.operation_list = operation_list
        self.emulator = None

    def get_raw_data(self):
        return self.raw_data

    def get_name_list(self):
        return self.name_list

    def get_operation_list(self):
        return self.operation_list

    # TODO spaeter loeschen
    def print_data(self):
        print self.raw_data
        print "\t",
        print self.name_list
        print "\t",
        print self.operation_list

