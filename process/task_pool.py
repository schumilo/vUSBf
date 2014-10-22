# Sergej Schumilo
#  Thread-safe pool for objects

from threading import Lock
import time


class task_pool(object):
    task_lock = Lock()
    no_tasks = False

    task_pool = []

    # add_task_rate:	min. number of added task per call
    # get_task_rate:	max. number of task per request
    # ttw_for_new_tasks:	time to time for new task if task_pool is empty
    def __init__(self, add_task_rate, get_task_rate, ttw_for_new_tasks, verbose_level):
        self.add_task_rate = add_task_rate
        self.get_task_rate = get_task_rate
        self.ttw_for_new_tasks = ttw_for_new_tasks
        self.verbose_level = verbose_level

    def get_more_tasks(self, num_of_tasks):

        if num_of_tasks > self.get_task_rate:
            num_of_tasks = self.get_task_rate

        self.task_lock.acquire()
        while len(self.task_pool) == 0:
            if self.no_tasks == True:
                self.task_lock.release()
                return None
            time.sleep(self.ttw_for_new_tasks)
        task_list = []

        if len(self.task_pool) < num_of_tasks:
            num_of_tasks = len(self.task_pool)

        for i in range(num_of_tasks):
            task_list.extend([self.task_pool.pop(0)])

        self.task_lock.release()
        return task_list


    def get_tasks(self, num_of_tasks):

        if num_of_tasks > self.get_task_rate:
            num_of_tasks = self.get_task_rate

        self.task_lock.acquire()
        #print "ENTER CRITICAL CODE"
        while len(self.task_pool) == 0:
            if self.no_tasks == True:
                print "NO"
                self.task_lock.release()
                return None
            time.sleep(self.ttw_for_new_tasks)
        task_list = []

        task_list = self.task_pool.pop(0)

        self.task_lock.release()
        return task_list

    def add_tasks(self, new_tasks):
        self.task_lock.acquire()
        # es folgen keine daten mehr
        if new_tasks == None:
            #	print "NO TASKS"
            no_tasks = True
        else:
            self.task_pool.extend(new_tasks)
            #print len(self.task_pool)
        self.task_lock.release()

    def get_add_task_rate(self):
        return self.add_task_rate

    def get_get_task_rate(self):
        return self.get_task_rate

    def get_ttw_for_new_tasks(self):
        return self.ttw_for_new_tasks

    def get_num_of_available_tasks(self):
        if self.task_pool is None:
            return 0
        return len(self.task_pool)

