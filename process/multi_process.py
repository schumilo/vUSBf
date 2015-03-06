"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

from multiprocessing import Process, Value, Queue, Semaphore
from qemu import qemu
from process import process
from print_performance_process import *
from test_generation.XMLParser import xml_parser
import signal
import time
import os
sys.path.append(os.path.abspath('../'))
import config

process_list = None
printPerf_process = None
network_requester_process = None


def signal_handler(a,b):
    kill_all()


def kill_all():
    global process_list, printPerf_process, network_requester_process
    if process_list is not None:
        for p in process_list:
            if p.is_alive:
                if type(p.pid) == int:
                    os.kill(p.pid, signal.SIGINT)

    if printPerf_process is not None:
        if printPerf_process.is_alive:
            if type(printPerf_process.pid) == int:
                os.kill(printPerf_process.pid, signal.SIGINT)

    if network_requester_process is not None:
        if network_requester_process.is_alive:
            if type(network_requester_process.pid) == int:
                os.kill(network_requester_process.pid, signal.SIGINT)
    sys.exit(0)


def multi_processing(process_number, target_object, exec_name, exec_list, exec_path, testcase_path, test_path,
                     reload_test, shuffle_test, payloads=None, file_name=None):
    global process_list
    global printPerf_process
    signal.signal(signal.SIGINT, signal_handler)

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

    if payloads is None:
        xml_tree = xml_parser(test_path_value, testcase_path_value, exec_path_value)
        xml_tree.calc_tests(exec_name)

        print "[*] Number of tests: " + str(xml_tree.get_number_of_elements())
        xml_tree.print_tree()
    else:
        xml_tree = payloads
        print "[*] Number of tests: " + str(xml_tree.get_number_of_elements())

    max_tasks = xml_tree.get_number_of_elements()
    sm_num_of_tasks = Value('i', 0)

    info_queue = Queue()
    queue_list = []
    process_list = []
    qemu_list = []

    process_lock = Semaphore(process_number)
    for i in range(process_number):
        process_lock.acquire()
    sem = Semaphore(config.PROCESS_REPAIR_SEMAPHORE)

    for i in range(process_number):
        queue_list.append(Queue())
        qemu_object = qemu("configurations/" + target_object, "/tmp/vusbf_" + str(i) + "_socket", i)
        qemu_list.append(qemu_object)
        if process_number == 1 and file_name is not None:
            process_list.append(Process(target=process, args=(
                "t" + str(i), qemu_object, sm_num_of_tasks, i, info_queue, queue_list[i], reload_test, sem, process_lock), kwargs={"file_postfix_name": file_name}))
        else:
            process_list.append(Process(target=process, args=(
                "t" + str(i), qemu_object, sm_num_of_tasks, i, info_queue, queue_list[i], reload_test, sem, process_lock)))

    printPerf_process = Process(target=printPerf, args=(max_tasks, sm_num_of_tasks))

    j = 0
    print "[*] Starting processes..."
    for e in process_list:
        e.start()
        time.sleep(0.1)
    print "[*] Preparing processes..."
    time.sleep(config.PROCESS_STARTUP_TIME)
    num_of_fin = 0
    num_of_processes = len(process_list)
    j = 0
    while True:
        if num_of_fin == num_of_processes:
            break
        if j == num_of_processes-num_of_fin:
            print "[*] Done..."
            printPerf_process.start()
            for i in range(num_of_processes):
                time.sleep(config.PROCESS_STARTUP_RATE)
                process_lock.release()

        process_num = info_queue.get()

        data = xml_tree.get_data_chunk(config.NUMBER_OF_JOBS_PER_PROCESS)
        if data is not None:
            queue_list[process_num].put(data)
            j += 1
        else:
            num_of_fin += 1
            queue_list[process_num].put(None)

    print "[*] Finished..."