import socket
import sys
import time
from protocol import *
import signal
from threading import Lock
import threading
import select

Socket = None
controller = None

# currently not in usage :-)
def signal_handler(signal, frame):
    global controller
    if controller != None:
        controller.close_connection()
        sys.exit(0)


class network_task_requester():
    cancel = False

    def __init__(self, ip, port, md5_vm, md5_overlay, sm_num_of_fin_tasks, info_queue, data_queue, worker_id,
                 verbose_level):
        self.md5_vm = md5_vm
        self.md5_overlay = md5_overlay
        self.sm_num_of_fin_tasks = sm_num_of_fin_tasks
        self.info_queue = info_queue
        self.data_queue = data_queue
        self.verbose_level = verbose_level
        self.connection_lock = Lock()
        self.thread = None
        self.worker_id = worker_id

        try:
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.connection.connect((ip, port))
        except socket.error:
            self.__put_error_code_to_queue("server not found")

        self.__connect()

    def __connect(self):

        # hello packet exchange
        data = vusbf_proto_header()
        data.Length = 0
        data.Type = 0
        self.__send_data(str(data))
        raw_data = self.__recv_data(self.connection, 8)
        hello = vusbf_proto_header(raw_data)
        # self.print_verbose("recv hello", self.verbose_level, 2)
        if not (hello.Type == 0 and hello.Length == 0):
            self.__put_error_code_to_queue("wrong type recv")

        # check TODO
        data = self.__recv_data(self.connection, 4 + 8)
        header = vusbf_proto_header(data)
        data = self.__recv_data(self.connection, header.Length)
        data = vusbf_proto_header()
        data.Length = 1
        data.Type = 6

        extra_data = vusbf_check_response("\x01")
        self.__send_data(str(data) + str(extra_data))

    # print "DONE"


    def send_data_request(self, number_of_tasks):


        # atomic block
        self.connection_lock.acquire()

        data = vusbf_proto_header()
        data.Type = 1
        data.Length = 4

        extra_data = vusbf_task()
        extra_data.Number_of_tasks = number_of_tasks

        #data.show()
        #print len(extra_data)
        #extra_data.show()

        self.__send_data(str(data) + str(extra_data))

        # atomic block end
        self.connection_lock.release()

    def start_listing_thread(self):
        if self.thread:
            return
        self.cancel = False
        self.thread = threading.Thread(target=self.connection_loop, args=())
        self.thread.start()

    def kill_listing_thread(self):
        self.cancel = True
        self.thread.join()
        self.thread = None

    def close_connection(self):
        try:
            self.kill_listing_thread()
        except:
            pass
        self.connection.close()

    def connection_loop(self):
        while True:

            fd = select.select([self.connection], [], [], 0.5)[0]
            #print fd
            if self.cancel:
                #print "EXIT"
                return
            if fd:
                if len(fd) > 0:

                    # atomic block
                    self.connection_lock.acquire()

                    raw_data = self.__recv_data(fd[0], 8)
                    #raw_data = fd[0].recv(8)
                    if len(raw_data) == 0:
                        # atomic block end
                        self.connection_lock.release()
                        return
                    header = vusbf_proto_header(raw_data)
                    #header.show()

                    # task response
                    if header.Type == 2:
                        #print "RESPONSE"
                        extra_data = None

                        # Keine Daten mehr
                        if not header.Length == 4:
                            raw_extra_data = self.__recv_all(fd[0], header.Length)
                            extra_data = cPickle.loads(raw_extra_data[4:])
                        self.__put_data_to_queue(extra_data)
                    #print "RECV TASK RESPONSE"

                    # sync request
                    elif header.Type == 3:
                        #	print "RECV SYNC REQUEST"

                        data = vusbf_proto_header()
                        data.Type = 4
                        data.Length = 4

                        extra_data = vusbf_sync()
                        extra_data.Number_of_fin_tasks = self.__get_sm_value()

                        self.__send_data(str(data) + str(extra_data))


                    # close connection
                    elif header.Type == 7:
                        #print "RECV END"
                        # atomic block end
                        self.connection_lock.release()
                        return

                    elif header.Type == None:
                        self.connection_lock.release()
                        return


                    # atomic block end
                    self.connection_lock.release()

    def __recv_all(self, fd, Length):
        data = ""
        recv_length = 0
        while True:
            #	print len(data)
            data += self.__recv_data(fd, (Length - len(data)))
            #data += fd.recv(Length-len(data))
            if len(data) == Length:
                return data


    # TODO Falls die Verbindung abbricht, sollen nur noch Nones in die Queue getan werden.
    # Gegebenenfalls sogar ein kompletter Abbruch des Programms
    # z.B info_queue.put(-1) --> EXIT
    # geprueft wird das am besten mit send/recv Wrapper methoden die exceptions abfangen
    # Das gilt uebrigens fuer alle Exceptions
    def __recv_data(self, fd, length):
        try:
            return fd.recv(length)
        except:
            self.__put_error_code_to_queue(sys.exc_info()[0])

    def __send_data(self, data):
        try:
            return self.connection.send(data)
        except:
            self.__put_error_code_to_queue(sys.exc_info()[0])

    def __put_data_to_queue(self, obj):

        # negativ - also Daten einfuegen
        #self.info_queue.put((self.worker_id*(-1)))
        self.data_queue.put(obj)

    #self.info_queue_lock.release()

    def __get_sm_value(self):
        return self.sm_num_of_fin_tasks.value

    def __put_error_code_to_queue(self, err_msg):
        self.data_queue.put(-1)
        print err_msg
        #raise Exception(err_msg)
        sys.exit(0)


def start_network_task_requester(server, port, md5_vm, md5_overlay, sm_num_of_fin_tasks, info_queue, data_queue, request_queue, worker_id, verbose_level):
    signal.signal(signal.SIGINT, signal_handler)
    controller = network_task_requester(server, port, md5_vm, md5_overlay, sm_num_of_fin_tasks, info_queue, data_queue, worker_id, verbose_level)
    #print "START"
    controller.start_listing_thread()


    # WAIT FOR REQUEST FROM MAIN PROCESS
    # SEND REQUEST TO MASTER
    # RECV DATA AND PUT THEM TO DATA QUEUE
    while True:
        value = request_queue.get()
        #print "REQUEST"
        if value == 0:
            controller.close()
            break
        else:
            controller.send_data_request(value)

    #print "EXIT"

