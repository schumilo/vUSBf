"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

from fileParser import *
import signal
import os

sys.path.append(os.path.abspath('../'))
import config

import pdb


class ForkedPdb2(pdb.Pdb):
    def interaction(self, *args, **kwargs):
        _stdin = sys.stdin
        try:
            sys.stdin = file('/dev/stdin')
            pdb.Pdb.interaction(self, *args, **kwargs)
        finally:
            sys.stdin = _stdin


class ForkedPdb(pdb.Pdb):
    def interaction(self, *args, **kwargs):
        _stdin = sys.stdin
        _stdout = sys.stdout
        try:
            sys.stdin = open('/home/sergej/log/debug_pipe_in', "r")
            sys.stdout = open('/home/sergej/log/debug_pipe_out', "w")
            pdb.Pdb(None, sys.stdin, sys.stdout).set_trace()
        finally:
            sys.stdin = _stdin
            sys.stdout = _stdout


def handle_pdb(sig, frame):
    print "INTERRUPT"
    ForkedPdb2().set_trace(frame)


qemu_obj = None


def signal_handler(signal, frame):
    global qemu_obj
    if qemu_obj is not None:
        qemu_obj.kill()
    sys.exit(0)


qemu_obj = None


def process(name, qemu, sm, worker_id, request_queue, response_queue, replay, sema, process_lock, file_postfix_name=None):
    global qemu_obj
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGUSR1, handle_pdb)

    log_postfix = str(worker_id)
    if file_postfix_name is not None:
        log_postfix = file_postfix_name

    f = open("./log/vusbf_log_" + str(worker_id), "a")
    f.write("\nPROCESS_ID: " + str(os.getpid()) + "\n")
    f.close()

    qemu_obj = qemu
    qemu_obj.set_file_name("./log/vusbf_log_" + str(worker_id))
    qemu_obj.start()
    time.sleep(1)

    i = 0
    tasks = []
    restore_counter = 0
    repair_counter = 0
    slow_start_counter = 0
    first_run = True
    while True:

        if restore_counter >= config.PROCESS_FAIL_COUNTER:
            # slow start exeption
            if not (
                            slow_start_counter < config.PROCESS_SLOW_START_THRESHOLD and restore_counter < config.PROCESS_SLOW_START_THRESHOLD_FAIL_COUNTER):
                sema.acquire()
                restore_counter = 0
                repair_counter += 1
                slow_start_counter = 0
                if repair_counter >= config.PROCESS_FAIL_REPAIR_COUNTER:
                    qemu.repair_image()
                    #time.sleep(config.PROCESS_TIMOUT_AFTER_REPAIR)
                    #qemu.reload()
                    time.sleep(config.PROCESS_TIMOUT_AFTER_REPAIR)
                else:
                    qemu.reload()
                sema.release()

        # Abbruchbedingung
        if len(tasks) == 0:
            request_queue.put(worker_id)
            tasks = response_queue.get()
            if first_run:
                process_lock.acquire()
            first_run = False
            if tasks is None:
                qemu_obj.kill()
                return

        tmp = tasks.pop(0)
        if not qemu.fire(tmp):
            tasks.append(tmp)
            restore_counter += 1
            continue

        if not qemu.log_qemu_output_select("./log/vusbf_log_" + log_postfix, str(tmp)):
            tasks.append(tmp)
            restore_counter += 1
            continue
        restore_counter = 0
        repair_counter = 0
        slow_start_counter += 1
        if replay:
            qemu.reload()

        qemu.check_if_image_corrupted()

        i += 1
        if i == config.PROCESS_NOTIFY_SHARED_MEMORY:
            sm.value += i
            i = 0
