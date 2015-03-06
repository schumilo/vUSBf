"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

import signal
import sys
import os
import time
import datetime

sys.path.append(os.path.abspath('../'))
import config



def signal_handler(signal, frame):
    sys.exit(0)


def getTime(timeValue):
    HOUR = 3600
    return "[" + str(int(str(datetime.datetime.fromtimestamp(timeValue).strftime('%j')),10)-1) + str(datetime.datetime.fromtimestamp(timeValue-HOUR).strftime(':%H:%M:%S')) + "]"

def getTimeDate(timeValue):
    return "[" + str(datetime.datetime.fromtimestamp(timeValue).strftime('%d/%m/%y:%H:%M:%S')) + "]"


def printPerf_Server(max_num_of_tasks, timeout, connection_list):
    # print "INFO_THREAD"
    start_time = time.time()

    while True:
        time.sleep(config.PRINT_PERFORMANCE_SERVER_TIMEOUT)
        total = 0
        for element in connection_list:
            total += element[1].value

        if total != 0:
            new_time = time.time()
            raw_value = float(total) / (float(new_time) - float(start_time))
            print "Jobs Done: " + str(total) + " \tPerformance: " + str(round(raw_value, 2)) + " t/s"
        else:
            print "\nClients:"

        for element in connection_list:
            print "\t" + element[0] + " \t",
            if element[2].is_alive():
                print "Condition: alive \t",
            else:
                print "Condition: dead  \t",
            print "Jobs Done: " + str(element[1].value) + "  \t",
            print "'Connection Time: " + getTimeDate(element[3])
        print ""
            #print element[1].value


def printPerf(max_num_of_tasks, sm_tasks_num):
    signal.signal(signal.SIGINT, signal_handler)
    start_time = time.time()
    old = 0
    while True:
        tmp = sm_tasks_num.value

        if tmp == max_num_of_tasks and max_num_of_tasks != 0:
            print getTimeDate(time.time()) + "\t Running time: " + getTime(time.time() - start_time )
            return
        else:
            new_time = time.time()
            raw_value = float(tmp) / (float(new_time) - float(start_time))
            value = round(raw_value, 2)

            if raw_value != 0:
                remaining_time = (max_num_of_tasks - tmp) / raw_value
            else:
                remaining_time = 0.0

            if remaining_time != 0.0 and max_num_of_tasks != 0:
                print getTimeDate(time.time()) + "\t" + str(value) + " t/s  " + "\tREAL: " + str(
                    round(float((tmp - old) / (float(config.PRINT_PERFORMANCE_TIMEOUT))), 2)) + " t/s" + "  \t" + str(
                    tmp) + "/" + str(max_num_of_tasks) + "  \t running time: " + getTime(
                    time.time() - start_time) + "\t remaining time: " + getTime(remaining_time )
            else:
                value = max_num_of_tasks
                if max_num_of_tasks == 0:
                    value = '-'
                print getTimeDate(time.time()) + "\t" + "\tREAL: " + str(
                    round(float((tmp - old) / (float(config.PRINT_PERFORMANCE_TIMEOUT))), 2)) + " t/s" + "  \t" + str(
                    tmp) + "/" + str(value) + "\t running time: " + getTime(time.time() - start_time )

            time.sleep(config.PRINT_PERFORMANCE_TIMEOUT)

        old = tmp

