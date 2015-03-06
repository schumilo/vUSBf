"""
    vUSBf: A KVM/QEMU based USB-fuzzing framework.
    Copyright (C) 2015  Sergej Schumilo, OpenSource Security Ralf Spenneberg
    This file is part of vUSBf.

    See the file LICENSE for copying permission.
"""
__author__ = 'Sergej Schumilo'

from monitor import monitor
import fcntl
from scapy.all import *
sys.path.append(os.path.abspath('../'))
import config


class linux_monitor(monitor):
    def __init__(self, qemu, filename):
        super(linux_monitor, self).__init__(qemu, filename)

    def monitor(self, title):
        return self.__monitor(title)[0]

    def __non_block_read(self, output):
        fd = output.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        try:
            return output.read()
        except:
            return ""

    def __monitor(self, title):
        data = ""
        try_to_read = 0
        while True:
            if data.count('\n') >= config.SERIAL_READ_MAX_LINES:
                data = data + config.MESSAGE_TOO_MUCH_DATA
                self.qemu.kill()
                self.qemu.start()
                break

            fd = select([self.qemu.process.stdout], [], [], config.SERIAL_READ_TIMEOUT)
            fd = fd[0]

            if len(fd) != 0:
                if fd[0]:
                    tmp = self.__non_block_read(fd[0])
                    if tmp == "":
                        break
                    else:
                        data = data + tmp
                        try_to_read = 0
                else:
                    break
            #else:
            #    pass
            try_to_read += 1

            if try_to_read >= config.SERIAL_READ_RETRIES:
                break

        try:
            tmp_data = data.split("\r")[1].translate(None, "\n ").replace("(qemu)", "").replace("replay", "").replace(
                "loadvm", "")
        except:
            return False, ""

        if len(tmp_data) == 0:
            return False, ""

        tmp_data = tmp_data.translate(None, "\x6c\x5b\x4b\x44\x6f\x61\x64\x76\x72\x65\x70")
        if len(tmp_data) == 0:
            return False, ""

        if str(Raw(tmp_data.replace("\x1b", ""))).encode("hex") == "":
            return False, ""

        _tmp = data
        data = data.split("\n")
        data2 = title + "\n"  # + data + delimiter
        f = open(self.filename, "a")
        f.write(data2)
        for line in data:
            if not line.startswith("(qemu)") and not line.startswith(
                    "QEMU ") and not "Clocksource tsc unstable (delta" in line:
                f.write(line + "\n")
        f.write(config.DELIMITER + "\n")
        f.close()
        return True, _tmp

