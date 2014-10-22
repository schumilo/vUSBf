from fileParser import *
import signal

qemu_obj = None

def signal_handler(signal, frame):
        global qemu
        if qemu_obj != None:
            qemu_obj.kill()
        sys.exit(0)

# main fuzzing process
def process(name, qemu, sm, worker_id, request_queue, response_queue, replay):
    global qemu_obj
    signal.signal(signal.SIGINT, signal_handler)
    qemu_obj = qemu
    qemu_obj.start
    qemu.set_file_name("./log/vusbf_log_" + str(worker_id))

    i = 0
    tasks = []
    while True:

        # Abbruchbedingung
        if len(tasks) == 0:
            request_queue.put(worker_id)
            tasks = response_queue.get()
            if tasks is None:
                return

        #print tasks
        tmp = tasks.pop(0)
        #print "TMP:"
        #print tmp
        #print "---" + str(len(tasks))
        qemu.fire(tmp, name)
        if not qemu.log_qemu_output_select("./log/vusbf_log_" + str(worker_id), "TEST #" + str(tmp[0]), "s"):
            qemu.fire(tmp, name)
        if replay:
            qemu.reload()

        qemu.check_if_image_corrupted(name)

        i += 1
        if i == 3:
            sm.value += i
            i = 0
