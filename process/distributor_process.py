__author__ = 'sergej'

from fileParser import *
from clustering.network_task_distributor import process
from multiprocessing import Process, Value, Queue
from threading import Thread
from fuzz_configuration.xml_parser import xml_parser
from random import shuffle
from print_performance_process import printPerf_Server

def distributor_process(host, port, info_queue, payload_queue):

    CONNECTION_RETRY_TIME = 1

    perf_list = []
    Thread(target=printPerf_Server, args=(0, 10, perf_list)).start()


    while True:
        try:
            Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            Socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            Socket.bind((host, port))
            while True:
                Socket.listen(1)
                Connection, Addr = Socket.accept()
                #print str(Addr[0]) + " connected..."
                sm = Value('i', 0)
                p = Process(target=process, args=(Connection, 2, 33, 444, sm, info_queue, payload_queue, 0))
                perf_list.append([Addr[0], sm, p, time.time()])
                p.start()
        except socket.error:
            time.sleep(CONNECTION_RETRY_TIME)


def server(host, port, exec_name, exec_list, exec_path, testcase_path, test_path, shuffle_test):
    info_queue = Queue()
    payload_queue = Queue()
    Process(target=distributor_process, args=(host, port, info_queue, payload_queue)).start()

    pos = 0
    path_prefix = ""
    data = xml_parser(path_prefix + test_path, path_prefix + testcase_path, path_prefix + exec_path).calc_tests(exec_name)

    if exec_list != []:
        new_data = []
        for e in exec_list:
            new_data.append(data[e])
        data = new_data

    if shuffle_test:
        shuffle(data)

    max = len(data)
    while True:
        number = info_queue.get()
        number = -5
        if pos+(number*-1) > max:
            if pos == max:
                return
            else:
                tmp = data[pos:max]
        else:
            tmp = data[pos: pos+(number*-1)]

        payload_queue.put(tmp)
        pos += len(tmp)
