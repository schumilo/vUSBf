"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""

from usbscapy import *

def print_descriptor(descriptor):
    if descriptor == None:
        return

    descriptor[0].show()
    for confDesc in descriptor[1]:
        confDesc[0].show()
        for ifDesc in confDesc[1]:
            ifDesc[0].show()
            for e in ifDesc[1]:
                e.show()


def patch_descriptor_length_fields(descriptor):
    if descriptor == None:
        return

    for configuration_num in range(len(descriptor[1])):
        patch_configuration_descriptor_length_field(descriptor, configuration_num)


def patch_configuration_descriptor_length_field(descriptor, configuration_num):
    confDesc = get_configuration_descriptor(descriptor, configuration_num)

    conf_length = 0
    for ifDesc in confDesc[1]:
        if_length = 0
        for e in ifDesc[1]:
            if_length += e.bLength
        conf_length += 9 + if_length
    confDesc[0].wTotalLength = 9 + conf_length


def get_configuration_descriptor(descriptor, configuration_num):
    # check Device Descriptor
    if descriptor == None:
        return None
    if descriptor[1] == None:
        return None
    if len(descriptor[1]) - 1 < configuration_num:
        return None

    return descriptor[1][configuration_num]


def get_interface_descriptor(descriptor, configuration_num, interface_num):
    configuration_descriptor = get_configuration_descriptor(descriptor, configuration_num)
    if configuration_descriptor == None:
        return None
    if configuration_descriptor[1] == None:
        return None
    if len(configuration_descriptor[1]) - 1 < interface_num:
        return None

    return configuration_descriptor[1][interface_num]


def add_new_descriptor_to_interface(descriptor, configuration_num, interface_num, new_descriptor):
    if new_descriptor == None:
        return False

    if not (type(new_descriptor) == usb_endpoint_descriptor or type(new_descriptor) == usb_hid_descriptor):
        return False

    interface_descriptor = get_interface_descriptor(descriptor, configuration_num, interface_num)
    if interface_descriptor == None:
        return False
    if interface_descriptor[1] == None:
        return False
    if interface_descriptor[0] == None:
        return False
    if interface_descriptor[0].bNumEndpoints == 255:
        return False

    if interface_descriptor[0].bNumEndpoints == None:
        interface_descriptor[0] = 0

    if type(new_descriptor) == usb_endpoint_descriptor:
        interface_descriptor[0].bNumEndpoints += 1

    interface_descriptor[1].append(new_descriptor)
    patch_descriptor_length_fields(descriptor)

    return True


def add_new_interface_to_configuration(descriptor, configuration_num, new_interface):
    if new_interface == None:
        return False

    if not type(new_interface) == usb_interface_descriptor:
        return False

    configuration_descriptor = get_configuration_descriptor(descriptor, configuration_num)
    if configuration_descriptor == None:
        return False
    if configuration_descriptor[1] == None:
        return False
    if configuration_descriptor[0] == None:
        return False
    if configuration_descriptor[0].bNumInterfaces == 255:
        return False

    if configuration_descriptor[0].bNumInterfaces == None:
        configuration_descriptor[0].bNumInterfaces = 0

    configuration_descriptor[0].bNumInterfaces += 1
    length = len(configuration_descriptor[1])
    configuration_descriptor[1].append([new_interface, []])
    configuration_descriptor[1][length - 1][0].bInterfaceNumber = length

    patch_descriptor_length_fields(descriptor)

    return True


def add_new_configuration_to_device_descriptor(descriptor, new_configuration):
    if new_configuration == None:
        return False

    if not type(new_configuration) == usb_configuration_descriptor:
        return False

    if descriptor == None:
        return False
    if descriptor[1] == None:
        return False
    if descriptor[0].bNumConfigurations == 255:
        return False

    if descriptor[0].bNumConfigurations == None:
        descriptor[0].bNumConfigurations = 0

    descriptor[0].bNumConfigurations += 1
    descriptor[1].append([new_configuration, []])
    patch_descriptor_length_fields(descriptor)

    return True


def del_interface_descriptor_object(descriptor, configuration_num, interface_num, object_num):
    interface_descriptor = get_interface_descriptor(descriptor, configuration_num, interface_num)

    if interface_descriptor == None:
        return False
    if interface_descriptor[1] == None:
        return False
    if interface_descriptor[0] == None:
        return False
    if len(interface_descriptor[1]) - 1 < object_num:
        return False

    # if you delete an endpointdescriptor, you also have to decrement bEndpointNum
    if interface_descriptor[1][object_num].bDescriptorType == 0x05:
        interface_descriptor[0].bNumEndpoints -= 1
    del interface_descriptor[1][object_num]

    patch_descriptor_length_fields(descriptor)

    return True


def del_interface_descriptor(descriptor, configuration_num, interface_num):
    interface_descriptor = get_interface_descriptor(descriptor, configuration_num, interface_num)
    if interface_descriptor == None:
        return False

    configuration_descriptor = get_configuration_descriptor(descriptor, configuration_num)
    configuration_descriptor[0].bNumInterfaces -= 1

    length = len(configuration_descriptor[1])

    del configuration_descriptor[1][interface_num]

    for i in range(length - 1 - interface_num):
        configuration_descriptor[1][i + interface_num][0].bInterfaceNumber -= 1

    return True


def del_configuration_descriptor(descriptor, configuration_num):
    if descriptor == None:
        return False
    if descriptor[0] == None:
        return False
    if descriptor[1] == None:
        return False

    length = len(descriptor[1])

    if length - 1 < configuration_num:
        return False

    del descriptor[1][configuration_num]

    descriptor[0].bNumConfigurations = length - 1

    return True
