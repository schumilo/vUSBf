class monitor(object):

    def __init__(self, qemu, filename):
	if qemu == None:
            raise Exception("qemu null pointer")	
	self.qemu = qemu
	if filename == None:
	    raise Exception("filename null pointer")
	self.filename = filename

    def log_reload(self):
        if self.filename != "":
            f = open(self.filename, "a")
            f.write("====================\tRELOAD\t====================\n");
            f.close()

    def monitor(self, name, title):
	pass
