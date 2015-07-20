"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

# monitor specific ######
# serial port read timeout (select timeout)
SERIAL_READ_TIMEOUT = 0.45
# maximal number of lines reading in 
SERIAL_READ_MAX_LINES = 1024
# maximal number of read retries
SERIAL_READ_RETRIES = 1
# fuzzing test print delimiter
DELIMITER = "\n#######################################################\n\n"
# fuzzing test SERIAL_READ_MAX_LINES message
MESSAGE_READ_MAX_LINES = "\n ------->>>>> MESSAGE_READ_MAX_LINES <<<<<-------"
# VM reload message
MESSAGE_VM_RELOAD = "====================\tRELOAD\t====================\n"
# log message for 'too much data to process' case
MESSAGE_TOO_MUCH_DATA = "\n ------->>>>> TOO MUCH DATA FROM STDOUT! <<<<<-------"
PRINT_VERBOSE_TEST_INFO = True

# usbemulator specific ######
# number of reconnects (QEMU usbredir interface)
NUMBER_OF_RECONNECTS = 3
# timeout between reconnects
TIME_BETWEEN_RECONNECTS = 0
# defined content of usbredir hello_packet
USB_REDIR_HELLO_PACKET = 'usbredirserver 0.6\x00\x00\x00\x00\x00\x00\xc0\x1f@\x00\x00\x00\x00\x00\x00\x9dj\x00\x00\x00\x00\x00uB\xe8h:\x7f\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xfe\x00\x00\x00'
# path to folder, which contains all available devices descriptors
DEV_DESC_FOLDER = "dev_desc/"
# unix socket timeout
UNIX_SOCKET_TIMEOUT = 0.5
# tcp socket timeout
TCP_SOCKET_TIMEOUT = 0.75
# connection to victim timeout
# (Linux: 0.2 - 0,75 / FreeBSD: 1.25 - 2.0)
CONNECTION_TO_VICTIM_TIMEOUT = 2.35
# max redir packet recv (deadlock prevention)
MAX_PACKETS = 500

# execution process specific ######
# fail counter
PROCESS_FAIL_COUNTER = 4
PROCESS_FAIL_REPAIR_COUNTER = 5
PROCESS_FAIL_SLEEP_A = 0.1
PROCESS_FAIL_SLEEP_B = 0.4
PROCESS_NOTIFY_SHARED_MEMORY = 1
PROCESS_TIMOUT_AFTER_REPAIR = 1.0
# threshold number of succesful testcases until qemu loadvm is used
PROCESS_SLOW_START_THRESHOLD = 5
PROCESS_SLOW_START_THRESHOLD_FAIL_COUNTER = 100
PROCESS_REPAIR_SEMAPHORE = 5

# debug specific ######
# define verbose level distinctions 
VERBOSE_LEVEL_PRINT_ERROR_MESSAGES = 4
VERBOSE_LEVEL_PRINT_RECV_DATA = 3
VERBOSE_LEVEL_PRINT_SEND_DATA = 2
VERBOSE_LEVEL_PRINT_INFO = 1
VERBOSE_LEVEL_PRINT_NOTHING = 0
# SIGUSR1 debug option
ENABLE_DEBUG_PROCESS = False
VERBOSE_LEVEL = 0

# performance process ######
PRINT_PERFORMANCE_TIMEOUT = 5.0
PRINT_PERFORMANCE_SERVER_TIMEOUT = 10.0

# multiprocessing specific ######
NUMBER_OF_JOBS_PER_PROCESS = 2048
PROCESS_STARTUP_TIME = 5.0
PROCESS_STARTUP_RATE = 0.5

# qemu specific #####
OVERLAY_FILE_PREFIX = "overlay_"
OVERLAY_FILE_POSTFIX = ".qcow2"

# non multiprocessing specifc #####
NUMBER_OF_JOBS_PER_PROCESS_NM = 100000
SLEEP_BETWEEN_TESTS = 0.2

# clustering specific #####
CLUSTERING_DEBUG_SERVER = False
CLUSTERING_DEBUG_CLIENT = False
CLUSTERING_CHUNK_SIZE = 2
CLUSTERING_CONNECTION_RETRY_TIME = 1

# execute mode specific #####
SERIAL_READ_RETRIES_EXECUTE_MODE = 8
PROCESS_SLOW_START_THRESHOLD_EXECUTE_MODE = 0
PROCESS_SLOW_START_THRESHOLD_FAIL_COUNTER_EXECUTE_MODE = 0
PROCESS_FAIL_REPAIR_COUNTER_EXECUTE_MODE = 2

# options #####
PRINT_DEVICE_DESCRIPTORS = False
