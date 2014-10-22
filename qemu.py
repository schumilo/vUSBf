# QEMU Basis Klasse

import shutil
import subprocess
import time
import os.path
from usbEmulator import *
import hashlib
from debug import *
import fcntl

from select import select


from monitor.monitor import *
from monitor.linux_monitor import *



class qemu:
    # defined verbose level distinctions in this class
    VERBOSE_LEVEL_PRINT_ERROR_MESSAGES = 4
    VERBOSE_LEVEL_PRINT_RECV_DATA = 3
    VERBOSE_LEVEL_PRINT_SEND_DATA = 2
    VERBOSE_LEVEL_PRINT_INFO = 1
    VERBOSE_LEVEL_PRINT_NOTHING = 0

    emu = None
    monitor = None

    file_name = ""


    config_qemu_bin = None
    config_kvm = None
    config_memory_size = None
    config_ram_file = None
    config_overlay = None
    config_usb_device_type = None
    config_snapshot = None
    config_qemu_extra = None
    config_overlay_folder = None

    config_args = ["qemu_bin", "kvm", "memory", "ram_file", "overlay_file", "device_type", "snapshot", "qemu_extra",
                   "overlay_folder"]

    call = ""

    def __read_config(self, config_file):
        if not os.path.isfile(config_file):
            print "FILE NOT FOUND " + config_file
            return False
        f = open(config_file)
        try:
            for line in f:
                if not line.startswith("#") and not line == "" and ":" in line:
                    arg = line.split(":")[0]
                    value = line.split(":")[1].replace(" ", "").replace("\t", "").replace("\n", "").replace("\"", "")

                    # qemu binary
                    if arg == self.config_args[0]:
                        if os.path.isfile(value):
                            self.config_qemu_bin = value

                    # kvm support
                    elif arg == self.config_args[1]:
                        if (value == "yes" or value == "no"):
                            if value == "yes":
                                self.config_kvm = True
                            else:
                                self.config_kvm = False
                    # memory size
                    elif arg == self.config_args[2]:
                        if value.isdigit():
                            self.config_memory_size = int(value)
                    # ram file
                    elif arg == self.config_args[3]:
                        if os.path.isfile(value):
                            self.config_ram_file = value
                    # overlay file
                    elif arg == self.config_args[4]:
                        if os.path.isfile(value):
                            self.config_overlay = value
                    # usb device type
                    elif arg == self.config_args[5]:
                        self.config_usb_device_type = value
                    # snapshot
                    elif arg == self.config_args[6]:
                        self.config_snapshot = value
                    # qemu extra
                    elif arg == self.config_args[7]:
                        self.config_qemu_extra = line.split(":")[1].replace("\n", "").replace("\"", "").replace("\t",
                                                                                                                " ")
                    # overlay folder
                    elif arg == self.config_args[8]:
                        #print value
                        if os.path.isdir(value):
                            self.config_overlay_folder = value
                            if self.config_overlay_folder.endswith("/"):
                                self.config_overlay_folder = self.config_overlay_folder[:-1]

        finally:
            f.close()

        if self.config_qemu_bin == None \
                or self.config_kvm == None \
                or self.config_memory_size == None \
                or self.config_ram_file == None \
                or self.config_overlay == None \
                or self.config_usb_device_type == None \
                or self.config_overlay_folder == None \
                or self.config_snapshot == None:
            print "READ CONFIG ERROR:"
            print self.config_qemu_bin
            print self.config_kvm
            print self.config_memory_size
            print self.config_overlay
            print self.config_usb_device_type
            print self.config_overlay_folder
            print self.config_snapshot
            return False
        else:
            return True

    def __gen_start_script(self, address):
        call = ""
        call += self.config_qemu_bin
        if self.config_kvm:
            call += " --enable-kvm"
        call += " -m " + str(self.config_memory_size)
        call += " -nographic"
        call += " -hdb " + self.config_ram_file
        call += " -hda " + self.config_overlay
        call += " -device " + self.config_usb_device_type
        call += " -loadvm " + self.config_snapshot
        call += " -serial mon:stdio"
        # call += " -monitor stdio"
        call += " -device usb-redir,chardev=usbchardev,debug=0 "

        if type(address) == list and len(address) == 2:
            call += " -chardev socket,server,id=usbchardev,port="
            call += str(address[1])
            call += ",host="
            call += str(address[0])
            call += ",nodelay,nowait"
        elif type(address) == str:
            call += " -chardev socket,server,id=usbchardev,nowait"
            call += ",path="
            #os.remove(address)
            call += address
        else:
            print "E"
            return None

        call += " " + self.config_qemu_extra

        return call

    # DATA_SOCKET LOESCHEN
    def __init__(self, config_file, log_file, data_socket, address, instance_id, verbose_level):

        self.instance_id = instance_id

        if not self.__read_config(config_file):
            raise Exception("read config error...")

        # copy overlay file
        self.config_overlay_backup = self.config_overlay

        if os.path.isfile(self.config_overlay_folder + "/" + "overlay_" + str(self.instance_id) + ".qcow2"):

            # md5_original = hashlib.md5(open(self.config_overlay, 'rb').read()).digest()
            #md5_copy = hashlib.md5(open(self.config_overlay_folder + "/" + "overlay_" + str(self.instance_id) + ".qcow2", 'rb').read()).digest()

            #if not str(md5_original) == str(md5_copy):
            #        if verbose_level >= self.VERBOSE_LEVEL_PRINT_INFO:
            #                print "copy overlay-file"
            pass
            #shutil.copy(self.config_overlay,
            #           self.config_overlay_folder + "/" + "overlay_" + str(self.instance_id) + ".qcow2")
            #else:
            #        if verbose_level >= self.VERBOSE_LEVEL_PRINT_INFO:
            #                print "md5 check: okay"

        else:
            # if verbose_level >= self.VERBOSE_LEVEL_PRINT_INFO:
            #        print "copy overlay-file"

            shutil.copy(self.config_overlay,
                        self.config_overlay_folder + "/" + "overlay_" + str(self.instance_id) + ".qcow2")

        self.config_overlay = self.config_overlay_folder + "/" + "overlay_" + str(self.instance_id) + ".qcow2"

        self.call = self.__gen_start_script(address)
        if self.call == None:
            raise Exception("address error...")

        if type(address) == str:
            self.emu = usb_emulator(address, 1, verbose_level)
        else:
            self.emu = usb_emulator(address, 0, verbose_level)

        #print self.call

    def __del__(self):
        if self.alive():
            self.kill()

    # start qemu
    def start(self):
	self.log_reload()
        devnull = open(os.devnull, 'wb')

        # print "START"
        args = filter(None, self.call.split(" "))
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1.0)
	
	
	#try:	
	#	str(self.process.pid)
	#except:
	#	self.start()


    def alive(self):
        if self.process == None:
            return False

        if self.process.poll() == None:
            return True
        else:
            return False
	


    def __non_block_read(self, output):
        fd = output.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        try:
            return output.read()
        except:
            return ""

    def set_file_name(self, file_name):
	self.file_name = file_name


    def log_reload(self):
	if self.monitor != None:
             self.monitor.log_reload()


    def log_qemu_output_select(self, fileName, title, name):
	if self.monitor == None:
	    self.monitor = linux_monitor(self, fileName)

	try:	
		return self.monitor.monitor(name, title)
	except:
		time.sleep(5)
		return self.monitor.monitor(name, title)
	
    # kill qemu
    def kill(self):
        try:
            self.process.stdout.close()
        except:
            pass
        try:
            self.process.stdin.close()
        except:
            pass
        try:
            self.process.kill()
        except:
            pass

    def check_if_image_corrupted(self, name):
        match = "Image is corrupt"
        fd = select([self.process.stderr], [], [], 0)
        fd = fd[0]
        #logDebug("msg_" + name, "TRY LOG " + str(fd))
        if len(fd) != 0:
        #if self.process.stderr.:
            #print "CORRUPTED " + name
            self.kill()
            shutil.copy(self.config_overlay_backup, self.config_overlay_folder + "/" + "overlay_" + str(self.instance_id) + ".qcow2")
            self.start()
        else:
            pass
            #print "OKAY"
        #fd[0].close()
        #pass

    # reload snapshot without killing qemu
    def reload(self):
	self.log_reload()
        if not self.alive():
            args = filter(None, self.call.split(" "))
            self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            #print "RELOAD"

        self.process.stdin.write("\1" + 'c' + "loadvm " + self.config_snapshot + '\n' + "\1" + 'c')

    # print "\1"+ 'c' + "loadvm " + self.config_snapshot + '\n' + "\1"+ 'c'
    #time.sleep(1)

    def fire(self, payload, name):
        #hello = 'usbredirserver 0.6\x00\x00\x00\x00\x00\x00\xc0\x1f@\x00\x00\x00\x00\x00\x00\x9dj\x00\x00\x00\x00\x00uB\xe8h:\x7f\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xfe\x00\x00\x00'

        logDebug("msg_" + name, "SETUP")
        self.emu.setup_payload(payload)
        logDebug("msg_" + name, "EXIT SETUP")
        while True:
            #	try:
            logDebug("msg_" + name, "FIRE")
            if not self.emu.fire(10, 2.4, name):
                logDebug("msg_" + name, "FIRE RESTART")
                try:
                    self.kill()
                except:
                    pass
                try:
                    self.start()
                except:
                    pass
                #time.sleep(0.25)
            else:
                logDebug("msg_" + name, "FIRE EXIT")
                break
        #	except:
        #		time.sleep(0.2)
        #		logDebug("msg_" + name, "FIRE ERROR")

        logDebug("msg_" + name, "FIRE EXIT")

