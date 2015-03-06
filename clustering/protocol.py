"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

from scapy.all import *

vusbf_type_enum = {
    0: "hello",			# This packet initialize the communication
    1: "task_request",		# This packet can be sent from the client to request new testcases
    2: "task_response",		# Response from the server, which contains testcases as pickle obj
    3: "sync_request",		# Heartbeat request from the server. It's needed for synchronization of the number of finished tasks  
    4: "sync_response",		# Response from the client. Contains the number of finished tasks
    5: "check_request",		# Request to check the given environment (VM , Overlay etc.)
    6: "check_response",	# Response for check_request
    7: "close_connection"}	# as the name says :-)


# Protocol header
class vusbf_proto_header(Packet):
    name = "VUSBF_ProtoHeader"
    fields_desc = [IntEnumField("Type", None, vusbf_type_enum),
                   IntField("Length", None)
    ]

# Protocol subheader (for task_request and task_response)
class vusbf_task(Packet):
    name = "VUSBF_Task"
    fields_desc = [IntField("Number_of_tasks", None)]

# Protocol subheader (for sync_request and sync_response)
class vusbf_sync(Packet):
    name = "VUSBF_Sync"
    fields_desc = [IntField("Number_of_fin_tasks", None)]

# Protocol subheader (no usage at the moment)
class vusbf_get(Packet):
    name = "VUSBF_Get"
    fields_desc = [XByteField("Drop_data", None)]

# Protocol subheader (for check_request)
class vusbf_check_request(Packet):
    name = "VUSBF_Check"
    fields_desc = [LongField("MD5_VM", None),
                   LongField("MD5_Overlay", None)
    ]

# Protocol subheader (for check_response)
class vusbf_check_response(Packet):
    name = "VUSBF_Check"
    fields_desc = [XByteField("Test_passed", None)]





