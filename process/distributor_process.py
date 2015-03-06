"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

from fileParser import *
from clustering.network_task_distributor import process
from multiprocessing import Process, Value, Queue
from threading import Thread
#from fuzz_configuration.xml_parser import xml_parser
from test_generation.XMLParser import  xml_parser
from random import shuffle
from print_performance_process import printPerf_Server
import signal
import config

server_process_list = []
print_perf_process = None
dist_process = None

def signal_handler2(signal, frame):
    exit(0)

def signal_handler(signal, frame):
    kill_all()

def kill_all_process():
    global server_process_list
    for e in server_process_list:
        if e is not None:
            if e.is_alive():
                e.terminate()

def kill_all():
    global dist_process
    print dist_process
    if dist_process is not None:
        print "A"
        if dist_process.is_alive():
            print "KILL"
            os.kill(dist_process.pid, signal.SIGINT)
            print "KILLKILL"
    sys.exit(0)

def distributor_process(host, port, info_queue, payload_queue):
    global server_process_list, print_perf_process
    signal.signal(signal.SIGINT, signal_handler2)

    perf_list = []
    print_perf_process = Thread(target=printPerf_Server, args=(0, 10, perf_list)).start()

    while True:
        try:
            Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            Socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            Socket.bind((host, port))
            while True:
                Socket.listen(1)
                Connection, Addr = Socket.accept()
                print str(Addr[0]) + " connected..."
                sm = Value('i', 0)
                p = Process(target=process, args=(Connection, 2, 33, 444, sm, info_queue, payload_queue, 5))
                server_process_list.append(p)
                perf_list.append([Addr[0], sm, p, time.time()])
                p.start()
        except socket.error:
            time.sleep(config.CLUSTERING_CONNECTION_RETRY_TIME)


def server(host, port, exec_name, exec_list, exec_path, testcase_path, test_path, shuffle_test):
    global dist_process
    signal.signal(signal.SIGINT, signal_handler)
    info_queue = Queue()
    payload_queue = Queue()
    dist_process = Process(target=distributor_process, args=(host, port, info_queue, payload_queue))
    dist_process.start()

    pos = 0
    path_prefix = "test_generation/"
    exec_path_value = path_prefix + "execution.xml"
    if exec_path != "":
        exec_path_value = exec_path

    testcase_path_value = path_prefix + "testcase.xml"
    if testcase_path != "":
        testcase_path_value = testcase_path

    test_path_value = path_prefix + "test.xml"
    if test_path != "":
        test_path_value = test_path

    xml_tree = xml_parser(test_path_value, testcase_path_value, exec_path_value)
    xml_tree.calc_tests(exec_name)

    print "[*] Number of tests: " + str(xml_tree.get_number_of_elements())
    xml_tree.print_tree()

    while True:
        try:
            number = info_queue.get()
        except:
            break
        tmp = xml_tree.get_data_chunk(config.CLUSTERING_CHUNK_SIZE)
        try:
            payload_queue.put(tmp)
        except:
            break
        if tmp is None:
            break
        pos += len(tmp)

    time.sleep(5)
    dist_process.terminate()
    print "[*] Done"
