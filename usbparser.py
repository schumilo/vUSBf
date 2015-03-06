"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

from usbscapy import *
import copy

# GENERIC CLASS
class parser(object):
    __raw = ""

    def __init__(self, raw):
        self.__raw = raw

    def getScapyPacket(self):
        return None

    def _getRaw(self):
        return self.__raw

# USBREDIR PARSER (USE THIS PARSER ONLY WITH DEVICE DATA)
class usbredir_parser(parser):
    scapyData = None

    def __init__(self, raw):
        if raw == None:
            raise Exception("illegal redirData")
        if len(raw) < 12:
            raise Exception("illegal redirData")

        parser.__init__(self,raw)
        self.scapyData = self.__parseRaw(raw)

        if len(self.scapyData) != len(raw):
            pass
            #print "ERROR " + str(len(self.scapyData)) + " " + str(len(raw))
            #print Raw(raw).show()

    def getScapyPacket(self):
        return self.scapyData

    def getScapyLayers(self):
        scapyLayers = []
        scapyLayer = copy.copy(self.scapyData)

        scapyLayers.append(type(scapyLayer))
        while scapyLayer.payload:
                scapyLayer = scapyLayer.payload
                scapyLayers.append(type(scapyLayer))

        return scapyLayers

    def modifyLayer(self, layerType, field, value):
        scapyLayer = self.scapyData
        if layerType == type(scapyLayer):
            setattr(scapyLayer, field, value)

        while scapyLayer.payload:
            scapyLayer = scapyLayer.payload
            if layerType == type(scapyLayer):
                setattr(scapyLayer, field, value)

    def __parseRaw(self, raw):

        header_layer = usbredirheader(raw[0:12])

        Htype = header_layer.Htype
        HLength = header_layer.HLength

        #if header_layer.Hid == 150761568:
        #	print hexdump(Raw(raw))
        #	pdb.set_trace()
        #	print "yo"

        if len(raw) == 12:
            return header_layer

        specific_layer = None
        for layer in redir_specific_type:
            if Htype == layer[0]:
                try:
                    specific_layer = layer[1](raw[12:HLength+12])
                except:
                    pass
                break

        # UNKOWN SPECIFIC REDIR HEADER
        if specific_layer == None:
            specific_layer = Raw(raw[12:HLength+12])
            header_layer = header_layer / specific_layer

        # CONTROL DATA REDIR HEADER
        elif Htype == 100:
            if specific_layer.haslayer(Raw):

                # IF REPORT DESC EXIT
                tmp_value = ""
                tmp_value = specific_layer.value
                tmp_value = tmp_value - 8704
                if tmp_value < 256 and tmp_value >= 0:
                    hid_report = usb_hid_report_descriptor(str(specific_layer.payload))
                    specific_layer.payload = None
                    return  header_layer / specific_layer / hid_report
                control_layer = control_packet_parser(specific_layer.load, specific_layer.request).getScapyPacket()
                specific_layer[Raw] = None
                header_layer = header_layer / specific_layer / control_layer
            else:
                header_layer = header_layer / specific_layer

        # BULK DTA
        elif Htype == 101 and specific_layer.haslayer(Raw):
            raw_layer = Raw(specific_layer.load)
            specific_layer[Raw] = None
            header_layer = header_layer / specific_layer / raw_layer

        raw = raw[HLength+12:]
        if raw != "":
            header_layer = header_layer / Raw(raw)
        return header_layer

                # EXTRACT REQUEST TYPE
                #       0 : self.handle_get_status_request,
                #       1 : self.handle_clear_feature_request,
                #       3 : self.handle_set_feature_request,
                #       5 : self.handle_set_address_request,
                #       6 : self.handle_get_descriptor_request,
                #       7 : self.handle_set_descriptor_request,
                #       8 : self.handle_get_configuration_request,
                #       9 : self.handle_set_configuration_request,
                #       10 : self.handle_get_interface_request,
                #       11 : self.handle_set_interface_request,
                #       12 : self.handle_synch_frame_request


# USB DESCRIPTOR PARSER (USB REDIR CONTROL DATA)
class control_packet_parser(parser):

    scapyData = None

    def __init__(self, raw, index):
        parser.__init__(self,raw)
        self.scapyData = self.__parseRaw(raw, index)
        if self.scapyData == None:
            raise Exception("Unknown data exception...")


    def getScapyPacket(self):
        return self.scapyData

    def __parseRaw(self, data, index):
        if data == "":
            return None

        # GENERIC DESCRIPTOR HEADER
        generic_descriptor_header = usb_generic_descriptor_header(data)
        #print generic_descriptor_header.bLength

        # DEVICE DESCRIPTOR
        if generic_descriptor_header.bDescriptorType == 0x01 and len(data) >= 18:
            # IF LEN == 5 AND TYPE == 1 -> REPORT DESCRIPTOR
            if generic_descriptor_header.bLength < 18:
                return Raw(data)
            newlayer = usb_device_descriptor(data[0:generic_descriptor_header.bLength])

        # CONFIGURATION DESCRIPTOR
        elif generic_descriptor_header.bDescriptorType == 0x2 and len(data) >= 9:
            newlayer = usb_configuration_descriptor(data[0:generic_descriptor_header.bLength])

        # INTERFACE DESCRIPTOR
        elif generic_descriptor_header.bDescriptorType == 0x04 and len(data) >= 9:
            newlayer = usb_interface_descriptor(data[0:generic_descriptor_header.bLength])

         # STRING LANGID DESCRIPTOR
        elif generic_descriptor_header.bDescriptorType == 0x03 and index == 0 and len(data) >= 4:
            newlayer = usb_string_descriptor_langid(data[:generic_descriptor_header.bLength])

        # STRING DESCRIPTOR
        elif generic_descriptor_header.bDescriptorType == 0x03 and index != 0 and len(data) >= 4:
            newlayer = usb_string_descriptor(data[:generic_descriptor_header.bLength])

        # HID DESCRIPTOR
        elif generic_descriptor_header.bDescriptorType == 0x09 and index != 0 and len(data) >= 4:
            newlayer = usb_hid_descriptor(data[:generic_descriptor_header.bLength])

        # ENDPOINT DESCRIPTOR
        elif generic_descriptor_header.bDescriptorType == 0x05 and len(data) >= 7:
            newlayer = usb_endpoint_descriptor(data[:generic_descriptor_header.bLength])

        # UNKNOWN DATA
        else:
            if len(data) >= generic_descriptor_header.bLength and generic_descriptor_header.bLength != 0:
                newlayer = Raw(data[:generic_descriptor_header.bLength])
            else:
                newlayer = Raw(data)

        # NEXT LAYER
        if len(data) >= generic_descriptor_header.bLength and generic_descriptor_header.bLength != 0:
            nextLayer = self.__parseRaw(data[generic_descriptor_header.bLength:], index)
            if nextLayer != None:
                newlayer = newlayer / nextLayer

        return newlayer

class data_bulk_parser(parser):

    scapyData = None
