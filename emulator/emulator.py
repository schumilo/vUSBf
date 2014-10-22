from scapy.all import *
class emulator(object):

    def __init__(self, fuzzer):
        if fuzzer == None:
            raise Exception("fuzzer object null pointer")
        # TODO type check fuzzer object
        self.fuzzer = fuzzer


    # fuzz data and return data as string
    def _fuzz_data(self, scapy_data):
        if scapy_data == None:
            return ""
        else:
            return self.fuzzer.post_fuzzing(scapy_data)

    def get_response(self, data):
        response = self._calc_response(data)
        return self._fuzz_data(response)

    def _calc_response(self, data):
        pass
