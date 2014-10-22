import sys

vid = ""
count = -1

f = open(sys.argv[1])
try:
	for line in f:
		if line.startswith("# List of known"):
			sys.exit(1)
		elif line.startswith("#"):
			pass
		elif line == "\n":
			pass
		elif line == " \n":
			pass
		else:
			if line.startswith("\t"):
				print vid + "",
				print line.replace("\t", "").replace("\n", "").split(" ")[0]
				count += 1
			elif line.startswith("\t\t"):
				print "IF"
				print line
			elif not line.startswith(" "):
				if count == 0:
					print vid + " ????"
				vid = line.replace("\n", "").split(" ")[0]
				count = 0
finally:
	f.close()
