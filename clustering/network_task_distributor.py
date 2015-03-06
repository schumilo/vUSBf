"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

from protocol import *
import select
import threading
from threading import Lock
import cPickle
import config
import signal

exit_flag = False

controller = None
timeout = 0

def signal_handler(signal, frame):
    global timeout, controller
    print "SIGHANDLER"
    if controller is not None:
        try:
            controller.stop_sync_callback()
        finally:
            print "Exit..."

class network_task_distributor:
    number_of_finished_tasks = 0

    # print some verbose stuff
    def print_verbose(self, data, verbose_level, verbose):
        if verbose_level >= verbose:
            print data

    # send synchronize request packet
    def synchronize(self):
        #print "REQ"
        # atomic block
        self.connection_lock.acquire()
        data = vusbf_proto_header()
        data.Type = 3
        data.Length = 0
        try:
            self.connection.send(str(data))
        except:
            # print "ERR"
            global exit_flag
            exit_flag = True
        self.connection_lock.release()
        # atomic block end

        self.timer = threading.Timer(self.sync_timeout, self.synchronize)
        self.timer.start()


    # constructor
    def __init__(self, connection, sync_timeout, md5_vm, md5_overlay, sm_num_of_fin_tasks, info_queue, data_queue,
                 verbose_level):
        self.connection = connection
        self.sync_timeout = sync_timeout
        self.md5_vm = md5_vm
        self.md5_overlay = md5_overlay
        self.sm_num_of_fin_tasks = sm_num_of_fin_tasks
        self.info_queue = info_queue
        self.data_queue = data_queue

        self.verbose_level = verbose_level
        self.connection_lock = Lock()

        self.__connect()


    # init connection to client (part of the constructor)
    def __connect(self):

        # recv and response hello packet
        # 8Byte + 4Byte = 12Byte
        raw_data = self.connection.recv(8)
        hello = vusbf_proto_header(raw_data)
        self.print_verbose("recv hello", self.verbose_level, 2)
        if not (hello.Type == 0 and hello.Length == 0):
            raise Exception("Wrong type recv")
        self.connection.send(str(hello))
        self.print_verbose("send hello", self.verbose_level, 2)


        # send check packet and wait for response
        check = vusbf_proto_header()
        check.Type = 5
        # LongField x 2 = 16Byte
        check.Length = 16

        check_layer = vusbf_check_request()
        check_layer.MD5_VM = self.md5_vm
        check_layer.MD5_Overlay = self.md5_overlay
        self.connection.send(str(check) + str(check_layer))
        self.print_verbose("send check", self.verbose_level, 2)

        raw_data = self.connection.recv(8)
        check_response = vusbf_proto_header(raw_data)
        if not (check_response.Type == 6 and check_response.Length != 0):
            raise Exception("Wrong type recv")
        raw_data = self.connection.recv(check_response.Length)
        self.print_verbose("recv check", self.verbose_level, 2)
        if vusbf_check_response(raw_data).Test_passed == 0:
            raise Exception("Test not passed")
        self.print_verbose("connection established", self.verbose_level, 2)

    # wait for incoming data
    def connection_loop(self):

        while True:

            fd = select.select([self.connection], [], [], self.sync_timeout)
            fd = fd[0]
            if fd:
                if exit_flag:
                    return
                if len(fd) > 0:
                    try:
                        # atomic block
                        self.connection_lock.acquire()

                        data = fd[0].recv(8)
                        #print "DATA: "+ str(data)
                        #print len(data)
                        #data.show()
                        if not len(data) == 8:
                            # atomic block end
                            self.connection_lock.release()
                            break
                        header = vusbf_proto_header(data)
                        if config.CLUSTERING_DEBUG_SERVER:
                            header.show()

                        if header.Type is None:
                            # atomic block end
                            self.connection_lock.release()
                            break

                        # end
                        elif header.Type == 7:
                            #print "RECV END"
                            self.connection_lock.release()
                            break

                        # task request
                        elif header.Type == 1:
                            #print "RECV TASK_REQUEST"
                            extra_data = fd[0].recv(header.Length)
                            header.Type = 2
                            # self.connection.send(str(header) + extra_data)



                            response = vusbf_proto_header()
                            response.Type = 2

                            reponse_extra = vusbf_task()
                            reponse_extra.Number_of_tasks = 100

                            response_payload = self.__request_data_from_queue()
                            #response_payload = Raw("fdfdsggfdfgddfdgdddfdfdf")
                            response.Length = len(str(reponse_extra)) + len(str(response_payload))
                            #response.show()
                            self.connection.send(str(response) + str(reponse_extra) + str(response_payload))

                        # sync response
                        elif header.Type == 4:
                            extra_data = self.connection.recv(header.Length)
                            self.__update_sm_value(vusbf_sync(extra_data).Number_of_fin_tasks)
                            #print "RECV SYNC RESPONSE " + str(vusbf_sync(extra_data).Number_of_fin_tasks)

                        # atomic block end
                        self.connection_lock.release()

                    except:
                        print "Oops"
                        #global exit_flag
                        #exit_flag = True
                        break
                else:
                    print "NOPE"


    def start_sync_callback(self):
        self.timer = threading.Timer(self.sync_timeout, self.synchronize)
        self.timer.start()


    def stop_sync_callback(self):
        self.timer.cancel()

    # #### process data exchange stuff #####

    def __request_data_from_queue(self):
        self.info_queue.put(-300)
        data = self.data_queue.get()
        #data = self.data_queue
        #print data
        #print "SEND"
        return Raw(cPickle.dumps(data))

        # put request in the info_queue
        # wait for data from data_queue
        # return data object
        pass


    def __return_data_to_queue(self):
        # TODO LATER
        #self.info_queue.put()
        # put request in the info_queue
        # send data to data_queue
        # fin
        pass

    def __update_sm_value(self, value):
        self.sm_num_of_fin_tasks.value = value
        #self.sm_num_of_fin_tasks.value("i", value)
        #print "GOT " + str(value)
        #update sem_value :-)
        pass


# data = fuzzer(100).gen_data(sys.argv[3], sys.argv[4])

# INFO QUEUE NEGATIVE WERT -> ENTSPRICHT DER ANZAHL DER BENOETIGTEN PACKETE
# WARTE AUF DATEN
# RACE CONDITION MOEGLICH...DUERFTE ABER ZU KEINEN PROBLEMEN FUEHREN

def process(Connection, sync_timeout, md5_vm, md5_overlay, sm_num_of_fin_tasks, info_queue, payload_queue, verbose_level):
    global timeout, controller
    signal.signal(signal.SIGTERM, signal_handler)
    timeout = sync_timeout
    if config.CLUSTERING_DEBUG_SERVER:
        verbose_level = 5
    controller = network_task_distributor(Connection, sync_timeout, md5_vm, md5_overlay, sm_num_of_fin_tasks,
                                          info_queue, payload_queue, verbose_level)
    controller.start_sync_callback()
    controller.connection_loop()
    #time.sleep(100)
    #print "EXXXX"
    controller.stop_sync_callback()



# PROCESS KOMMUNIKATION:
# Positive worker_id -> Datenanfrage
# Negative worker_id -> Daten werden zurueck gegeben (communications error)
# sharedmemory variable dient zum Abgleich der Anzahl der aktuell erledigen Aufgaben
# Datenqueue (max_packet x max_num_of_packtes) 


#sync_timeout, md5_vm, md5_overlay, verbose_level)
