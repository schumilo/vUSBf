from monitor import monitor
import sys
import os
from select import select
import subprocess
import fcntl

sys.path.append(os.path.abspath('../'))
from debug import *

class linux_monitor(monitor):

    def __init__(self, qemu, filename):
	super(linux_monitor, self).__init__(qemu, filename)

    def __non_block_read(self, output):
        fd = output.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        try:
            return output.read()
        except:
            return ""

    def monitor(self, name, title):
        delimiter = "\n#######################################################\n\n"
        data = ""
        timeout = 0.25
        # TODO
        # #time.sleep(0.75)

        max_num_of_lines = 1024

        max_try_to_read = 100000
        try_to_read = 0
	
	# DEBUG MESSAGE
        logDebug("msg_" + name, "START LOG " + str(self.qemu.process.pid))
        while True:
            if data.count('\n') >= max_num_of_lines:
		
		# DEBUG MESSAGE
                logDebug("msg_" + name, "TOO MUCH DATA ERROR")
                data = data + "\n ------->>>>> TOO MUCH DATA FROM STDOUT! <<<<<-------"
                self.qemu.kill()
                self.qemu.start()
                break

            # DEBUG MESSAGE
            logDebug("msg_" + name, "TRY LOG ")
            fd = select([self.qemu.process.stdout], [], [], timeout)
            fd = fd[0]

            # DEBUG MESSAGE
            logDebug("msg_" + name, "TRY LOG " + str(fd))
            if len(fd) != 0:
                if fd[0]:

                    # DEBUG MESSAGE
                    logDebug("msg_" + name, "READ LINE")
                    tmp = self.__non_block_read(fd[0])

                    # DEBUG MESSAGE
                    logDebug("msg_" + name, "READ LINE EXIT")
                    if tmp == "":
                        break
                    else:
                        data = data + tmp

                        # DEBUG MESSAGE
                        logDebug("msg_" + name, "READ LEN:" + str(len(tmp)))
                else:
                    break
            else:
                break
            try_to_read += 1
	
            if try_to_read == max_try_to_read:
		#print "BREAK!"
		break
            #    self.qemu.kill()
            #    self.qemu.start()
            #    return False

        if data == "":
            self.qemu.kill()
            self.qemu.start()
            return False

        # DEBUG MESSAGE
        logDebug("msg_" + name, "EXIT LOOP LOG")
        data = data.split("\n")
        data2 = title + "\n"  # + data + delimiter
        f = open(self.filename, "a")
        f.write(data2)
        for line in data:
            if not line.startswith("(qemu)") and not line.startswith(
                    "QEMU ") and not "Clocksource tsc unstable (delta" in line:
                f.write(line + "\n")
        f.write(delimiter + "\n")
        f.close()
        return True

###############

