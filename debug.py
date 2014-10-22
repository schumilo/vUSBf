import threading
import time
import datetime


# defined verbose level distinctions 
VERBOSE_LEVEL_PRINT_ERROR_MESSAGES = 4
VERBOSE_LEVEL_PRINT_RECV_DATA = 3
VERBOSE_LEVEL_PRINT_SEND_DATA = 2
VERBOSE_LEVEL_PRINT_INFO = 1
VERBOSE_LEVEL_PRINT_NOTHING = 0

# # GENERIC STUFF ##
def getTime(timeValue):
    return "[" + str(datetime.datetime.fromtimestamp(timeValue).strftime('%H:%M:%S')) + "]"

## PRINT DEBUG MSG ##
debug = False
output_lock = threading.Lock()
debug2 = False

# PRINT DEBUG MSG TO STDOUT
def printDebug(msg):
    global debug

    if debug:
        output_lock.acquire()
        print getTime(time.time()) + "\t" + "DEBUG\t" + msg
        output_lock.release()


# WRITE DEBUG MSG TO FILE
def logDebug(fileName, msg):
    global debug2

    if debug2:
        f = open("/tmp/" + fileName, "a")
        f.write(getTime(time.time()) + "\t" + msg + "\n")
        f.close()


## PRINT PERFORMANCE ##
notifyTask_lock = threading.Lock()
num_of_finished_tasks = 0

# FINISHED TASKS POOL
def notifyTask():
    global notifyTask_lock
    global num_of_finished_tasks

    notifyTask_lock.acquire()
    num_of_finished_tasks += 1
    notifyTask_lock.release()


# PRINT PERFORMANCE
"""
class printPerformance(threading.Thread):

	max_num_of_tasks = 0
	start_time = 0.0
	timeout = 0

		def __init__(self, max_num_of_tasks, timeout):
				threading.Thread.__init__(self)
		self.start_time = time.time()
		self.max_num_of_tasks = max_num_of_tasks
		self.timeout = timeout

		def run(self):
				global notifyTask_lock
			global num_of_finished_tasks
		
		while True:
			notifyTask_lock.acquire()
				tmp = num_of_finished_tasks
				notifyTask_lock.release()

			if tmp == self.max_num_of_tasks:
				print getTime(time.time()) + "\t time: " + getTime(time.time() - self.start_time - 3600)
				return
			else:
				new_time = time.time()
				raw_value = float(tmp) / (float(new_time) - float(self.start_time))
				value = round(raw_value, 2)

				# remaining time
				if raw_value != 0:
					remaining_time = (self.max_num_of_tasks - tmp) / raw_value
				else:
					remaining_time = 0.0
				
				if remaining_time != 0.0:
					print getTime(time.time()) + "\t" + str(value) + " tests/sec  " + "  \t" + str(tmp) + "/" + str(self.max_num_of_tasks) + "  \t running time: " + getTime(time.time() - self.start_time - 3600) + "\t remaining time: " + getTime(remaining_time - 3600)
				else:
					print getTime(time.time()) + "\t" + str(value) + " tests/sec  " + "  \t" + str(tmp) + "/" + str(self.max_num_of_tasks) + "\t running time: " + getTime(time.time() - self.start_time - 3600)
				
				time.sleep(self.timeout)
"""
