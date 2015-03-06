"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""

from usbscapy import *

class usbdescFileParser:
    descriptor_types = ["Device Descriptor:",
                        "Configuration Descriptor:",
                        "Interface Descriptor:",
                        "Endpoint Descriptor:",
                        "HID Descriptor:",
                        "** UNRECOGNIZED:"
    ]

    data = ""
    speed = 2


    def __init__(self, filePath):
        try:
            f = open(filePath)
            data = ""
            for line in f:
                if not line.startswith("Bus") and not line.startswith("Speed"):
                    data = data + line
                elif line.startswith("Speed"):
                    value = line.split("Speed")[1].replace(" ", "").replace("\t", "").replace("\n", "")
                    if value == "Low":
                        self.speed = 0
                    elif value == "Full":
                        self.speed = 1
                    elif value == "High":
                        self.speed = 2
                    elif value == "Super":
                        self.speed = 3
                    elif value == "Unkown":
                        self.speed = 255
                    else:
                        self.speed = 255
            f.close()

            self.data = data.replace("HID Device Descriptor:", "HID Descriptor:")
        except:
            raise Exception("file not found")

    def parse(self):
        data = self.data
        descriptor_types = self.descriptor_types

        data = data.replace("HID Device Descriptor:", "HID Descriptor:")

        for descriptor_type in descriptor_types:
            data = data.replace(descriptor_type, "; " + descriptor_type)

        data = data.split(";")

        connectPacket = connect_redir_header()
        interface_info = if_info_redir_header()
        endpoint_info = ep_info_redir_header()
        scapyPacket = None
        devDesc = None
        confDesc = None

        # build payload
        for line in data:

            newLayer = self.__parseDescriptor(line)

            # add device descriptor to list
            if type(newLayer) == usb_device_descriptor:
                devDesc = [newLayer, []]
            # add donfiguration descriptor to list
            elif type(newLayer) == usb_configuration_descriptor and devDesc != None:
                devDesc[1].append([newLayer, []])
            # add interface descriptor to list
            elif type(newLayer) == usb_interface_descriptor and devDesc[1] != None:
                devDesc[1][len(devDesc[1]) - 1][1].append([newLayer, []])
            # add endpoint / HID descriptor to list
            elif (type(newLayer) == usb_endpoint_descriptor or type(newLayer) == usb_hid_descriptor) and devDesc[
                1] != None:
                if devDesc[1][len(devDesc[1]) - 1] != None:
                    devDesc[1][len(devDesc[1]) - 1][1][len(devDesc[1][len(devDesc[1]) - 1][1]) - 1][1].append(newLayer)



            # scapyPacket
            if newLayer != None:
                if scapyPacket == None:
                    scapyPacket = newLayer
                else:
                    scapyPacket = scapyPacket / newLayer

        # connect packet
        connectPacket.speed = self.speed
        connectPacket.device_class = scapyPacket.bDeviceClass
        connectPacket.device_subclass = scapyPacket.bDeviceSubClass
        connectPacket.device_protocol = scapyPacket.bDeviceProtocol
        connectPacket.vendor_id = scapyPacket.isVendor
        connectPacket.product_id = scapyPacket.idProduct
        connectPacket.device_version_bcd = scapyPacket.bcdDevice


        # interface info
        tmp = scapyPacket
        interface = []
        interface_class = []
        interface_subclass = []
        interface_protocol = []

        while True:
            if tmp.haslayer(usb_interface_descriptor):
                if tmp[usb_interface_descriptor].bInterfaceNumber != None:
                    interface.append(tmp[usb_interface_descriptor].bInterfaceNumber)
                    interface_class.append(tmp[usb_interface_descriptor].bInterfaceClass)
                    interface_subclass.append(tmp[usb_interface_descriptor].bInterfaceSubClass)
                    interface_protocol.append(tmp[usb_interface_descriptor].bInterfaceProtocol)
                tmp = tmp[usb_interface_descriptor].payload
            else:
                break

        interface_count = len(interface)
        for i in range(32 - interface_count):
            interface.append(0)
            interface_class.append(0)
            interface_subclass.append(0)
            interface_protocol.append(0)

        interface_info.interface_count = interface_count
        interface_info.interface = interface
        interface_info.interface_class = interface_class
        interface_info.interface_subclass = interface_subclass
        interface_info.interface_protocol = interface_protocol

        # endpoint_info
        datacopy = copy.deepcopy(scapyPacket)
        interface_num = 0

        # bmAttributes Bits 0..1 Transfer Type
        #   00 = Control
        #   01 = Isochronous
        #   10 = Bulk
        #   11 = Interrupt

        ep_info_type = []
        ep_info_interval = []
        ep_info_interface = []
        ep_info_max_packet_size = []
        for i in range(32):
            ep_info_type.append(255)  # INVALID
            ep_info_interval.append(0)
            ep_info_interface.append(0)
            ep_info_max_packet_size.append(0)

        # DEFAULT CONTROL EP
        ep_info_type[0] = 0
        ep_info_type[16] = 0

        while True:
            if type(datacopy) == usb_interface_descriptor:
                interface_num = datacopy.bInterfaceNumber
            elif type(datacopy) == usb_endpoint_descriptor:
                if not (datacopy.bmAttribut == None or datacopy.bInterval == None or datacopy.wMaxPacketSize == None):
                    # CALC POSITION
                    pos = 0
                    if datacopy.bEndpointAddress >= 0x80:
                        pos = (datacopy.bEndpointAddress - 0x80) + 16
                    else:
                        pos = datacopy.bEndpointAddress

                    ep_info_type[pos] = (datacopy.bmAttribut % 4)
                    ep_info_interval[pos] = datacopy.bInterval
                    ep_info_interface[pos] = interface_num
                    ep_info_max_packet_size[pos] = datacopy.wMaxPacketSize
            datacopy = datacopy.payload
            if str(datacopy) == "":
                break

        endpoint_info.ep_type = ep_info_type
        endpoint_info.interval = ep_info_interval
        endpoint_info.interface = ep_info_interface
        endpoint_info.max_packet_size = ep_info_max_packet_size

        return devDesc, confDesc, connectPacket, interface_info, endpoint_info

    def __parser(self, desc, data):
        data = data.split("\n")
        i = 1
        while i < len(data):
            split = filter(None, (data[i].split(" ")))
            if len(split) >= 2:

                # HEX VALUES
                if split[1].startswith("0x"):
                    split[1] = int(split[1], 16)

                # OTHER HEX VALUES
                elif "." in split[1]:
                    split[1] = split[1].replace(".", "")
                    if len(split[1]) != 4:
                        split[1] = "0" + split[1]
                        split[1] = "0x" + split[1]
                    split[1] = int(split[1], 16)

                # mA VALUES
                elif "mA" in split[1]:
                    split[1] = int(split[1].replace("mA", ""), 10) / 2

                # INT VALUES
                else:
                    try:
                        split[1] = int(split[1], 10)
                    except:
                        split[1] = "VOID"

                # SOME FIXES
                if split[0] == "idVendor":
                    split[0] = "isVendor"
                elif split[0] == "bMaxPacketSize0":
                    split[0] = "bMaxPacketSize"
                elif split[0] == "MaxPower":
                    split[0] = "bMaxPower"
                elif split[0] == "bmAttributes":
                    split[0] = "bmAttribut"
                elif split[0] == "iSerial":
                    split[0] = "iSerialNumber"

                if split[0] == "bDescriptorType":
                    pass

                setattr(desc, split[0], split[1])
            i += 1
        return desc

    def __parseDescriptor(self, data):
        descriptor_types = self.descriptor_types
        # RAW DATA
        if "** UNRECOGNIZED:" in data:
            rawData = data.split(":")[1].replace(" ", "").replace("\n", "")
            i = 0
            newRawData = ""
            while i < len(rawData):
                newRawData = newRawData + chr(int(rawData[i:i + 2], 16))
                i += 2

            return Raw(newRawData)

        desctypes = str(descriptor_types)
        desctype = data.split(":")[0][1:] + ":"
        if not desctype in desctypes:
            return None
        else:
            if desctype == descriptor_types[0]:
                desc = usb_device_descriptor()
                return self.__parser(desc, data)
            elif desctype == descriptor_types[1]:
                desc = usb_configuration_descriptor()
                return self.__parser(desc, data)
            elif desctype == descriptor_types[2]:
                desc = usb_interface_descriptor()
                return self.__parser(desc, data)
            elif desctype == descriptor_types[3]:
                desc = usb_endpoint_descriptor()
                return self.__parser(desc, data)
            elif desctype == descriptor_types[4]:
                desc = usb_hid_descriptor()
                self.__parser(desc, data)
                desc.bDescriptorType = 33
                desc.bDescriptorType2 = 34
                return desc

#test = usbdescFileParser("./dev_desc/desc3.txt").parse()

