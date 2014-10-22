# Sergej Schumilo 2014
#
#
from multiprocessing import Process, Value, Queue

from task_pool import *
from qemu import qemu
from process import process
from print_performance_process import *
import signal
import time
import os
from clustering.network_task_requester import start_network_task_requester

process_list = None
printPerf_process = None
network_requester_process = None


def signal_handler(signal, frame):
    kill_all()


def kill_all():
    if process_list != None:
        for p in process_list:
            if p.is_alive:
                if type(p.pid) == int:
                    os.kill(p.pid, signal.SIGINT)

    if printPerf_process != None:
        if printPerf_process.is_alive:
            if type(printPerf_process.pid) == int:
                os.kill(printPerf_process.pid, signal.SIGINT)

    if network_requester_process != None:
        if network_requester_process.is_alive:
            if type(network_requester_process.pid) == int:
                os.kill(network_requester_process.pid, signal.SIGINT)
    sys.exit(0)


def client(process_number, target_object, host, port, reload_test):
    signal.signal(signal.SIGINT, signal_handler)
    number_of_threads = process_number

    tasks_pool = task_pool(50, 2000, 2, 0)
    max_tasks = 100000

    sm_num_of_tasks = Value('i', 0)

    i = 0

    info_queue = Queue()
    queue_list = []
    process_list = []
    qemu_list = []

    for i in range(number_of_threads):
        queue_list.append(Queue())
        qemu_object = qemu("configurations/" + target_object, "", "", "/tmp//tmp/vusbf_" + str(i) + "_socket", i, 0)
        qemu_list.append(qemu_object)
        qemu_object.start()
        time.sleep(0.1)
        process_list.append(Process(target=process, args=("t" + str(i), qemu_object, sm_num_of_tasks, i, info_queue, queue_list[i], reload_test)))

    printPerf_process = Process(target=printPerf, args=(max_tasks, 10, sm_num_of_tasks))

    for e in process_list:
        e.start()

    payload_queue = Queue()
    request_queue = Queue()
    request_queue.put(300000)
# start network task requester

    network_requester_process = Process(target=start_network_task_requester, args=(host, port, "sdsds", "sasas", sm_num_of_tasks, info_queue, payload_queue, request_queue, 1337, 2))
    network_requester_process.start()


    num_of_fin = 0
    num_of_processes = len(process_list)

    printPerf_started = False

    while True:
        if num_of_fin == num_of_processes:
            # kill all
            break

        process_num = info_queue.get()

        if tasks_pool.get_num_of_available_tasks() == 0:
            request_queue.put(300000)
            data = payload_queue.get()
            if type(data) == int:
                if data == -1:
                    kill_all()
            tasks_pool.add_tasks(data)
            #print tasks_pool.get_num_of_available_tasks()
        #else:
            #print "REQ"
        data = tasks_pool.get_more_tasks(2000)
            #print data
        if data is not None:
            queue_list[process_num].put(data)
            if not printPerf_started:
                printPerf_process.start()
                printPerf_started = True
        else:
            num_of_fin += 1
            queue_list[process_num].put(None)
