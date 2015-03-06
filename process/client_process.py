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
import signal
import time
from clustering.network_task_requester import start_network_task_requester

process_list = None
printPerf_process = None
network_requester_process = None

def signal_handler(signal, frame):
    kill_all()

def kill_all():
    global process_list
    global network_requester_process
    if process_list is not None:
        for p in process_list:
            if p.is_alive:
                p.terminate()

    if network_requester_process is not None:
        if network_requester_process.is_alive:
            try:
                network_requester_process.terminate()
                network_requester_process.join()
            except AttributeError:
                pass
    sys.exit(0)


def client(process_number, target_object, host, port, reload_test):
    global process_list
    global network_requester_process
    signal.signal(signal.SIGINT, signal_handler)
    number_of_threads = process_number

    max_tasks = 100000
    sm_num_of_tasks = Value('i', 0)

    info_queue = Queue()
    queue_list = []
    process_list = []
    process_lock = Semaphore(process_number)
    for i in range(process_number):
        process_lock.acquire()
    sem = Semaphore(config.PROCESS_REPAIR_SEMAPHORE)

    for i in range(number_of_threads):
        queue_list.append(Queue())
        qemu_object = qemu("configurations/" + target_object, "/tmp/vusbf_" + str(i) + "_socket", i)
        process_list.append(Process(target=process, args=("t" + str(i), qemu_object, sm_num_of_tasks, i, info_queue, queue_list[i], reload_test, sem, process_lock)))

    printPerf_process = Process(target=printPerf, args=(0, sm_num_of_tasks))

    payload_queue = Queue()
    request_queue = Queue()
    request_queue.put(config.CLUSTERING_CHUNK_SIZE)

    j = 0
    print "[*] Starting processes..."
    for e in process_list:
        e.start()
        time.sleep(0.1)
    print "[*] Preparing processes..."
    time.sleep(config.PROCESS_STARTUP_TIME)

    # start network task requester
    network_requester_process = Process(target=start_network_task_requester, args=(host, port, "sdsds", "sasas", sm_num_of_tasks, info_queue, payload_queue, request_queue, 1337, 2))
    network_requester_process.start()

    num_of_fin = 0
    num_of_processes = len(process_list)
    j = 0
    no_data = False
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

        if not no_data:
            request_queue.put(config.CLUSTERING_CHUNK_SIZE)
            data = payload_queue.get()
        else:
            data = None
        if data is not None:
            queue_list[process_num].put(data)
            j += 1
        else:
            num_of_fin += 1
            queue_list[process_num].put(None)
            no_data = True

    print "[*] Finished..."
    printPerf_process.terminate()
    network_requester_process.terminate()