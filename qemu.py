"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""

import shutil
from usbEmulator import *
from monitor.linux_monitor import *
import config


class qemu:
    file_name = ""
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
                        if value == "yes" or value == "no":
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
                        # print value
                        if os.path.isdir(value):
                            self.config_overlay_folder = value
                            if self.config_overlay_folder.endswith("/"):
                                self.config_overlay_folder = self.config_overlay_folder[:-1]

        finally:
            f.close()

        if self.config_qemu_bin is None \
                or self.config_kvm is None \
                or self.config_memory_size is None \
                or self.config_ram_file is None \
                or self.config_overlay is None \
                or self.config_usb_device_type is None \
                or self.config_overlay_folder is None \
                or self.config_snapshot is None:
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
            call += address
        else:
            print "E"
            return None
        call += " " + self.config_qemu_extra
        return call

    # def __init__(self, config_file, log_file, data_socket, address, instance_id, verbose_level)
    def __init__(self, config_file, address, instance_id):

        self.process = None
        self.monitor = None
        self.instance_id = instance_id

        if not self.__read_config(config_file):
            raise Exception("read config error...")

        # copy overlay file
        self.config_overlay_backup = self.config_overlay

        if os.path.isfile(self.config_overlay_folder + "/" + config.OVERLAY_FILE_PREFIX + str(self.instance_id) + config.OVERLAY_FILE_POSTFIX):

            os.remove(self.config_overlay_folder + "/" + config.OVERLAY_FILE_PREFIX + str(self.instance_id) + config.OVERLAY_FILE_POSTFIX)
            shutil.copy(self.config_overlay,
                        self.config_overlay_folder + "/" + config.OVERLAY_FILE_PREFIX + str(self.instance_id) + config.OVERLAY_FILE_POSTFIX)

        else:
            if config.VERBOSE_LEVEL >= config.VERBOSE_LEVEL_PRINT_INFO:
                print "copy overlay-file"

            shutil.copy(self.config_overlay,
                        self.config_overlay_folder + "/" + config.OVERLAY_FILE_PREFIX + str(self.instance_id) + config.OVERLAY_FILE_POSTFIX)

        self.config_overlay = self.config_overlay_folder + "/" + config.OVERLAY_FILE_PREFIX + str(self.instance_id) + config.OVERLAY_FILE_POSTFIX
        self.call = self.__gen_start_script(address)
        if self.call is None:
            raise Exception("address error...")

        if type(address) == str:
            self.emu = usb_emulator(address, 1)
        else:
            self.emu = usb_emulator(address, 0)

    def __del__(self):
        if self.alive():
            self.kill()

    def start(self):
        self.log_reload()
        self.process = subprocess.Popen(filter(None, self.call.split(" ")), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1.0)

    def alive(self):
        if self.process is None:
            return False

        if self.process.poll() is None:
            return True
        else:
            return False

    def set_file_name(self, file_name):
        self.file_name = file_name

    def log_reload(self):
        if self.monitor is not None:
            self.monitor.log_reload()

    def log_qemu_output_select(self, file_name, title):
        try:
            if self.monitor is None:
                self.monitor = linux_monitor(self, file_name)
            return self.monitor.monitor(title)
        except:
            return False

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

    def check_if_image_corrupted(self):
        fd = select([self.process.stderr], [], [], 0)
        fd = fd[0]
        if len(fd) != 0:
            self.repair_image()
        else:
            pass
            # fd[0].close()

    def repair_image(self):
        self.kill()
        os.remove(self.config_overlay_folder + "/" + config.OVERLAY_FILE_PREFIX + str(self.instance_id) + config.OVERLAY_FILE_POSTFIX)
        shutil.copy(self.config_overlay_backup,
                    self.config_overlay_folder + "/" + config.OVERLAY_FILE_PREFIX + str(self.instance_id) + config.OVERLAY_FILE_POSTFIX)
        self.start()

    def reload(self):
        self.log_reload()
        if not self.alive():
            self.start()
        try:
            self.process.stdin.write("\1" + 'c' + "loadvm " + self.config_snapshot + '\n' + "\1" + 'c')
        except:
            pass

    def fire(self, payload):
        self.emu.setup_payload(payload)
        return self.emu.execute()