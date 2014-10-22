import time
import signal
import sys
from debug import getTime

def signal_handler(signal, frame):
        global qemu
        sys.exit(0)

def printPerf_Server(max_num_of_tasks, timeout, connection_list):
    #print "INFO_THREAD"
    start_time = time.time()
    time.sleep(timeout)

    while True:

        total = 0
        for element in connection_list:
            total += element[1].value

        if total != 0:
            new_time = time.time()
            raw_value = float(total) / (float(new_time) - float(start_time))
            print "TOTAL: " + str(total) + " Tests \tTests per seconds: " + str(round(raw_value, 2))
        else:
            print "\nINFO: "

        for element in connection_list:
            print "->\tClient: " + element[0] + " |\t",
            if element[2].is_alive():
                print "Condition: alive |\t",
            else:
                print "Condition: dead  |\t",
            print "Jobs Done: " + str(element[1].value) + "  |\t",
            print "Unix-time: " + str(element[3])
            #print element[1].value
        time.sleep(timeout)


def printPerf(max_num_of_tasks, timeout, sm_tasks_num):
    signal.signal(signal.SIGINT, signal_handler)
    start_time = time.time()
    while True:
        tmp = sm_tasks_num.value

        if tmp == max_num_of_tasks:
            print getTime(time.time()) + "\t time: " + getTime(time.time() - start_time - 3600)
            return
        else:
            new_time = time.time()
            raw_value = float(tmp) / (float(new_time) - float(start_time))
            value = round(raw_value, 2)

            if raw_value != 0:
                remaining_time = (max_num_of_tasks - tmp) / raw_value
            else:
                remaining_time = 0.0

            if remaining_time != 0.0:
                print getTime(time.time()) + "\t" + str(value) + " tests/sec  " + "  \t" + str(tmp) + "/" + str(max_num_of_tasks) + "  \t running time: " + getTime(time.time() - start_time - 3600) + "\t remaining time: " + getTime(remaining_time - 3600)
            else:
                print getTime(time.time()) + "\t" + str(value) + " tests/sec  " + "  \t" + str(tmp) + "/" + str(max_num_of_tasks) + "\t running time: " + getTime(time.time() - start_time - 3600)

            time.sleep(timeout)

