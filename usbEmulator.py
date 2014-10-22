
from usbparser import *
from fileParser import *

from emulator.enumeration_abortion import abortion_enumeration
from emulator.enumeration import enumeration
from emulator.hid import hid

from fuzzer import fuzzer



from debug import *


class usb_emulator:
    # test
    #bulk_emu = bulk_fuzz()

    # connecting specific values
    NUMBER_OF_RECONNECTS = 3
    TIME_BETWEEN_RECONNECTS = 1

    # defined verbose level distinctions in this class
    VERBOSE_LEVEL_PRINT_ERROR_MESSAGES = 4
    VERBOSE_LEVEL_PRINT_RECV_DATA = 3
    VERBOSE_LEVEL_PRINT_SEND_DATA = 2
    VERBOSE_LEVEL_PRINT_NOTHING = 1

    # connection specific member variables
    port = 0
    ip = ""
    unix_socket = ""

    # payload specific member variables
    payload = []
    hello_packet = ""
    connect_packet = None
    if_info_packet = None
    ep_info_packet = None

    verbose_level = 0

    enum_emulator = None


    # address_type:
    #	0:	[IP, TCP]
    #	1:	[Unix-Socket]
    def __init__(self, victim_address, address_type, verbose_level):

        if victim_address == None or address_type == None:
            raise Exception("Victim address errror")

        if address_type == 0:
            if len(victim_address) != 2:
                raise Exception("Victim address error - expected format is [IP, PORT]")
            else:
                if victim_address[0] == None or victim_address[1] == None:
                    raise Exception("Victim address error - expected format is [IP, PORT]")
            self.ip = victim_address[0]
            self.port = victim_address[1]

        elif address_type == 1:
            #if not os.path.isfile(victim_address):
            #	raise Exception("Unix-socket does not exist")
            self.unix_socket = victim_address
        else:
            raise Exception("Unknown address type")

        self.verbose_level = verbose_level

        self.hello_packet = 'usbredirserver 0.6\x00\x00\x00\x00\x00\x00\xc0\x1f@\x00\x00\x00\x00\x00\x00\x9dj\x00\x00\x00\x00\x00uB\xe8h:\x7f\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xfe\x00\x00\x00'


    def setup_payload(self, payload):
    #def setup_payload(self, payload, if_info_packet, ep_info_packet, hello_packet, connect_packet, string_descriptor, no):

        #(payload[0], payload[3], payload[4], hello, payload[2], string_descriptor_list[0],
        #print "dev_desc/" + payload[1][1][1]


        data = usbdescFileParser("dev_desc/" + payload[1][1][1]).parse()

        self.payload = data[0]
        self.if_info_packet = data[3]
        self.ep_info_packet = data[4]
        self.connect_packet = data[2]


        fuzzer_obj = fuzzer(payload[2])

        fuzzer_obj.set_descriptor(self.payload)

        if payload[1][0][1] == "enumeration":
            self.enum_emulator = enumeration(fuzzer_obj)
        elif payload[1][0][1] == "enumeration_abortion":
            self.enum_emulator = abortion_enumeration(fuzzer_obj)
	elif payload[1][0][1] == "hid":
            self.enum_emulator = hid(fuzzer_obj)
        else:
            raise Exception("Unknown emulator")

        #self.enum_emulator


    #self.enum_emulator = abortion_enumeration(fuzzer_obj)
    #self.enum_emulator = hid_emulator(payload, string_descriptor, None, None)
    #self.enum_emulator = abortion_enumeration_emulator(payload, string_descriptor, int(sys.argv[6]))

    def fire(self, init_timeout, timeout, name):
        logDebug("msg_" + name, "FIRE CONNECT")
        connection_to_victim = self.__connect_to_server(init_timeout)
        if connection_to_victim == None:
            return False
        logDebug("msg_" + name, "FIRE CONNECT EXIT")
        if connection_to_victim == None:
            print "Unable to connect to victim..."
            return False
        logDebug("msg_" + name, "FIRE SEND")
        return self.__connection_loop(connection_to_victim, timeout)


    def __get_hello_packet(self):
        pkt = usbredirheader()
        pkt.Htype = 0
        pkt.HLength = 68
        pkt.Hid = 0
        pkt = pkt / Raw(self.hello_packet)
        return str(pkt)

    def __get_connect_packet(self):
        pkt = usbredirheader()
        pkt.Htype = 1
        pkt.HLength = 10
        pkt.Hid = 0
        pkt = pkt / Raw(str(self.connect_packet))
        return str(pkt)

    def __get_if_info_packet(self):
        pkt = usbredirheader()
        pkt.Htype = 4
        pkt.HLength = 132
        pkt.Hid = 0
        pkt = pkt / Raw(str(self.if_info_packet))
        return str(pkt)


    def __get_ep_info_packet(self):
        pkt = usbredirheader()
        pkt.Htype = 5
        pkt.HLength = 160
        pkt.Hid = 0
        pkt = pkt / Raw(str(self.ep_info_packet))
        return str(pkt)


    def __connection_loop(self, connection_to_victim, timeout):

        # connect to redir guest
        connection_to_victim.settimeout(1.35)
        try:
            self.__print_data(self.__recv_data(80, connection_to_victim), True)
            self.__print_data(self.__send_data(self.__get_hello_packet(), connection_to_victim), False)
            self.__print_data(self.__send_data(self.__get_if_info_packet(), connection_to_victim), False)
            self.__print_data(self.__send_data(self.__get_ep_info_packet(), connection_to_victim), False)
            self.__print_data(self.__send_data(self.__get_connect_packet(), connection_to_victim), False)
        except:
            return False

        backup_packet = None
        new_packet = None
        #connection_to_victim.settimeout(10)
        success = False
        while True:
            time.sleep(random.uniform(0.001, 0.01))
            # recv usbredir-header
            try:
                if new_packet != None:
                    backup_packet = new_packet
                new_packet = usbredirheader(self.__recv_data_dont_print(12, connection_to_victim))
                if new_packet.Htype == -1:
                    return True
                #break
                raw_data = self.__recv_data_dont_print(new_packet.HLength, connection_to_victim)
                raw_data = str(new_packet) + raw_data
                new_packet = usbredir_parser(raw_data).getScapyPacket()

            except:
                self.__print_error("NO DATA - ERROR")
                return True
            #break

            #new_packet.show()
            # Hello
            if new_packet.Htype == 0:
                self.__print_data(str(new_packet), True)

            #elif new_packet.Htype == -1:
            #	break

            # Reset
            elif new_packet.Htype == 3:
                self.__print_data(str(new_packet), True)

            elif new_packet.Htype == 6:
                self.__print_data(str(new_packet), True)

                new_packet.Htype = 8
                new_packet.HLength = new_packet.HLength + 1
                new_packet.payload = Raw('\x00' + str(new_packet.payload))
                self.__print_data(self.__send_data(str(new_packet), connection_to_victim), False)
                connection_to_victim.settimeout(0.5)
            #return True
            #print "SET CONFIG"

            elif new_packet.Htype == 15:
                self.__print_data(str(new_packet), True)

                new_packet.Htype = 17
                new_packet.HLength = new_packet.HLength + 1
                new_packet.payload = Raw('\x00' + str(new_packet.payload))
                self.__print_data(self.__send_data(str(new_packet), connection_to_victim), False)
                return True

            #elif new_packet.Htype == 6:
            #	print "SET CONFIG"
            #	return True

            elif new_packet.Htype == 21:
                return True
                pass
            #break
            #print "CANCEL PACKET"

            # Control Data
            elif new_packet.Htype == 100:
                success = True
                # recv request
                self.__print_data(raw_data, True)

                # send response
                response = str(self.enum_emulator.get_response(str(new_packet)))
                #print "GET RESPONSE"
                self.__print_data(self.__send_data(response, connection_to_victim), False)
            elif new_packet.Htype == 101:
                #response = str(self.bulk_emu.get_response(str(raw_data)))
                self.__send_data(response, connection_to_victim)
            elif new_packet.Htype == 103:

                new_packet.HLength = 4
                Raw(raw_data).show()
                interrupt_payload = data_interrupt_redir_header(raw_data[12:])
                Raw(str(new_packet) + str(interrupt_payload)).show()
                interrupt_payload.status = 0
                interrupt_payload.load = None
                print "SEND"
                Raw(str(new_packet) + str(interrupt_payload)).show()
                self.__send_data(str(new_packet) + str(interrupt_payload), connection_to_victim)
            #else:
            #	print "EXIT"
            #	return True

            # TODO ZAEHLER EINBAUEN !!
            #time.sleep(0.5)
            #return True

        return success


    def __print_data(self, data, recv):
        if self.verbose_level >= self.VERBOSE_LEVEL_PRINT_RECV_DATA:
            if recv:
                print "RECV: Type ",
            else:
                print "SEND: Type ",

            try:
                print usbredir_type_enum[usbredirheader(data).Htype]
            except:
                print usbredirheader(data).Htype
            Raw(data).show()
            print ""

    # if verbose level 3 or higher print packet content
    def __recv_data(self, length, connection_to_victim):
        try:
            data = connection_to_victim.recv(length)
            return data
        except:
            return ""

    def __recv_data_dont_print(self, length, connection_to_victim):
        #return self.__recv_data(length, connection_to_victim)
        return connection_to_victim.recv(length)


    def __send_data(self, data, connection_to_victim):
        try:
            connection_to_victim.send(data)
            return data
        except:
            return ""

    def __print_error(self, msg):
        if self.verbose_level >= self.VERBOSE_LEVEL_PRINT_ERROR_MESSAGES:
            print "ERROR:\t" + msg


    def __connect_to_server(self, init_timeout):
        num_of_tries = 0
        connection_to_victim = None
        while True:
            try:
                if self.unix_socket == "":
                    connection_to_victim = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    connection_to_victim.settimeout(0.5)
                    connection_to_victim.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    connection_to_victim.connect((self.ip, self.port))
                #	connection_to_victim.settimeout(init_timeout)
                else:
                    #	print self.unix_socket
                    connection_to_victim = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    connection_to_victim.settimeout(0.75)
                    connection_to_victim.connect(self.unix_socket)
                #       connection_to_victim.settimeout(init_timeout)
                break
            except:
                num_of_tries += 1
                if self.NUMBER_OF_RECONNECTS == num_of_tries:
                    #	print "ERROR"
                    #self. __print_error("CONNECTING TRY #" + str(num_of_tries))
                    #time.sleep(self.TIME_BETWEEN_RECONNECTS)
                    return None
        return connection_to_victim
			
