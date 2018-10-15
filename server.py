import socket
import subprocess
import datetime
import re
import md5

cur_folder = "./sharedfolder1"
port = 6000
s = socket.socket()
host = ""
files = []

def validate(date_text):
    try:
        date = datetime.datetime.strptime(date_text, "%d/%m/%Y-%H:%M")
    except ValueError:
        return False
    return True

def get_date(filename):
	filedate = subprocess.check_output(["date", "-r", filename, "+%F %T"])
	filedate = filedate.strip('\n')
	filedate = datetime.datetime.strptime(filedate, '%Y-%m-%d %H:%M:%S')	
	return filedate

def get_octal(filename):
	octal = subprocess.check_output(["stat", "-f", "%A %a %N", filename])
	octal = octal.strip('\n')
	octal = octal.split()
	return octal[0]

def update_file_structure():
	del files[:]
	lsout = subprocess.check_output(["ls", "-lh", cur_folder])
	lsout = lsout.split('\n')
	linecount = 0
	for line in lsout:
		line = line.split()
		if line and (line[0][0] == '-' or line[0][0] == 'd'):
			linecount += 1
			if line[1] == '1':
				filetype = "File"
			else:
				filetype = "Directory"
			filename = line[8]
			filedate = get_date(cur_folder + '/' + filename)
			permissions = get_octal(cur_folder + '/' + filename)
			filesize = line[4]
			filehash = md5.new()
			f = open(cur_folder + '/' + filename,'r')
			l = f.read(1024)
			while (l):
				filehash.update(l)
				l = f.read(1024)
			f.close()
			checksum = filehash.digest()
			file = {
				"filename": filename,
				"filesize": filesize,
				"timestamp": filedate,
				"filetype": filetype,
				"permissions": permissions,
				"checksum": checksum
			}
			files.append(file)

def index_cmd(cmd, conn, addr):
	shortlist = 0
	regex = 0
	longlist = 0
	length = len(cmd)
	if length >= 2:
		if cmd[1] == "longlist":
			longlist = 1
		elif cmd[1] == "shortlist":
			shortlist = 1
			if length == 4:
				if validate(cmd[2]):
					d1 = datetime.datetime.strptime(cmd[2], '%d/%m/%Y-%H:%M')
				else:
					conn.send(format(len("Error: Invalid date format"), '04d'))
					conn.send("Error: Invalid date format")
					return
				if validate(cmd[3]):
					d2 = datetime.datetime.strptime(cmd[3], '%d/%m/%Y-%H:%M')
				else:
					conn.send(format(len("Error: Invalid date format"), '04d'))
					conn.send("Error: Invalid date format")
					return
			elif length < 4:
				conn.send(format(len("Error: Too few arguments"), '04d'))
				conn.send("Error: Too few arguments")
				return
			else:
				conn.send(format(len("Error: Too few arguments"), '04d'))
				conn.send("Error: Too many arguments")
				return
		elif cmd[1] == "regex":
			regex = 1
			if length == 3:
				pattern = cmd[2]
				pattern = pattern + '$'
			elif length == 2:
				conn.send(format(len("Error: Pattern required"), '04d'))
				conn.send("Error: Pattern required")
				return
			else:
				conn.send(format(len("Error: Too many arguments"), '04d'))
				conn.send("Error: Too many arguments")
				return
		else:
			conn.send(format(len("Error: Invalid argument: " + cmd[1]), '04d'))
			conn.send("Error: Invalid argument: " + cmd[1])
			return
	else:
		conn.send(format(len("Error: Too few arguments"), '04d'))
		conn.send("Error: Too few arguments")
		return

	conn.send(format(len("Success"), '04d'))
	conn.send("Success")
	update_file_structure()
	filecount = 0
	for file in files:
		if shortlist == 1:
			if file["timestamp"] >= d1 and file["timestamp"] <= d2:
				filecount += 1		
		elif regex == 1:
			if re.match(pattern, file["filename"]):
				filecount += 1
		else:
			filecount += 1

	conn.send(format(filecount, '04d'))
	if filecount == 0:
		return

	for file in files:
		if shortlist == 1:
			if file["timestamp"] >= d1 and file["timestamp"] <= d2:
				conn.send(format(len(str(file["filename"])), '04d'))
				conn.send(str(file["filename"]))

				conn.send(format(len(str(file["filesize"])), '04d'))
				conn.send(str(file["filesize"]))

				conn.send(format(len(str(file["timestamp"])), '04d'))
				conn.send(str(file["timestamp"]))

				conn.send(format(len(str(file["filetype"])), '04d'))
				conn.send(str(file["filetype"]))

				conn.send(format(len(str(file["checksum"])), '04d'))
				conn.send(str(file["checksum"]))
		elif regex == 1:
			if re.match(pattern, file["filename"]):
				conn.send(format(len(str(file["filename"])), '04d'))
				conn.send(str(file["filename"]))

				conn.send(format(len(str(file["filesize"])), '04d'))
				conn.send(str(file["filesize"]))

				conn.send(format(len(str(file["timestamp"])), '04d'))
				conn.send(str(file["timestamp"]))

				conn.send(format(len(str(file["filetype"])), '04d'))
				conn.send(str(file["filetype"]))

				conn.send(format(len(str(file["checksum"])), '04d'))
				conn.send(str(file["checksum"]))
		else:
			conn.send(format(len(str(file["filename"])), '04d'))
			conn.send(str(file["filename"]))

			conn.send(format(len(str(file["filesize"])), '04d'))
			conn.send(str(file["filesize"]))

			conn.send(format(len(str(file["timestamp"])), '04d'))
			conn.send(str(file["timestamp"]))

			conn.send(format(len(str(file["filetype"])), '04d'))
			conn.send(str(file["filetype"]))

			conn.send(format(len(str(file["checksum"])), '04d'))
			conn.send(str(file["checksum"]))

def hash_cmd(cmd, conn, addr):
	update_file_structure()
	verify = 0
	checkall = 0
	found = 0
	checksum = ''
	timestamp = ''
	length = len(cmd)
	if length >= 2:
		if cmd[1] == "checkall":
			checkall = 1
		elif cmd[1] == "verify":
			verify = 1
			if length == 3:
				filename = cmd[2]
				for file in files:
					if file["filename"] == filename:
						found = 1
						checksum = str(file["checksum"])
						timestamp = str(file["timestamp"])
						break
						
			elif length < 3:
				conn.send(format(len("Error: Too few arguments"), '04d'))
				conn.send("Error: Too few arguments")
				return
			else:
				conn.send(format(len("Error: Too few arguments"), '04d'))
				conn.send("Error: Too many arguments")
				return
		else:
			conn.send(format(len("Error: Invalid argument: " + cmd[1]), '04d'))
			conn.send("Error: Invalid argument: " + cmd[1])
			return
	else:
		conn.send(format(len("Error: Too few arguments"), '04d'))
		conn.send("Error: Too few arguments")
		return

	if (verify == 1 and found == 0):
		conn.send(format(len("Error: File doesn't exist"), '04d'))
		conn.send("Error: File doesn't exist")
		return	

	conn.send(format(len("Success"), '04d'))
	conn.send("Success")

	if verify == 1:
		conn.send(format(len(checksum), '04d'))
		conn.send(checksum)
		conn.send(format(len(timestamp), '04d'))
		conn.send(timestamp)

	elif checkall == 1:
		conn.send(format(len(files), '04d'))
		for file in files:
			checksum = str(file["checksum"])
			timestamp = str(file["timestamp"])
			filename = str(file["filename"])
			conn.send(format(len(filename), '04d'))
			conn.send(filename)
			conn.send(format(len(checksum), '04d'))
			conn.send(checksum)
			conn.send(format(len(timestamp), '04d'))
			conn.send(timestamp)

def download_cmd(cmd, conn, addr):
	update_file_structure()
	found = 0
	index = 0
	filename = ''
	length = len(cmd)
	if length == 3:
		if cmd[1] == "tcp" or cmd[1] == "udp":
			filename = cmd[2]
			for file in files:
				if (file["filename"] == filename and file["filetype"] == "File"):
					found = 1
					break
		else:
			conn.send(format(len("Error: Invalid argument: " + cmd[1]), '04d'))
			conn.send("Error: Invalid argument: " + cmd[1])
			return
	else:
		conn.send(format(len("Error: Too few arguments"), '04d'))
		conn.send("Error: Too few arguments")
		return

	if found == 0:
		conn.send(format(len("Error: File doesn't exist"), '04d'))
		conn.send("Error: File doesn't exist")
		return	

	conn.send(format(len("Success"), '04d'))
	conn.send("Success")

	new_port = 0
	client_ip = addr[0]
	conn_type = cmd[1]
	udp_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	if conn_type == "udp":
		new_port = int(conn.recv(4))

	for file in files:
		if (file["filename"] == filename and file["filetype"] == "File"):
			if conn_type == "tcp":
				conn.send(format(len(str(file["checksum"])), '04d'))
				conn.send(str(file["checksum"]))

				conn.send(format(len(str(file["permissions"])), '04d'))
				conn.send(str(file["permissions"]))

			else:
				udp_s.sendto(format(len(str(file["checksum"])), '04d'), (client_ip, new_port))
				udp_s.sendto(str(file["checksum"]), (client_ip, new_port))

				udp_s.sendto(format(len(str(file["permissions"])), '04d'), (client_ip, new_port))
				udp_s.sendto(str(file["permissions"]), (client_ip, new_port))

			f = open(cur_folder + '/' + filename,'r')
			l = f.read(1024)
			while (l):
				conn.send("Next")
				if conn_type == "tcp":
					conn.send(format(len(l), '04d'))
					conn.send(l)
				else:
					udp_s.sendto(format(len(l), '04d'), (client_ip, new_port))
					udp_s.sendto(l, (client_ip, new_port))
				l = f.read(1024)
			f.close()
			conn.send("Done")
			break

	udp_s.close()
			

def parse_cmd(cmd, conn, addr):
	f = open('log.txt', 'a+')
	f.write(str(datetime.datetime.now()) + '\n' +cmd + '\n\n')
	f.close()
	if not cmd:
		return 0
	cmd = cmd.split()
	if cmd[0] == "exit":
		return 1
	elif cmd[0] == "download":
		download_cmd(cmd, conn, addr)
	elif cmd[0] == "hash":
		hash_cmd(cmd, conn, addr)
	elif cmd[0] == "index":
		index_cmd(cmd, conn, addr)
	else:
		conn.send(format(len("Error: Invalid command"), '04d'))
		conn.send("Error: Invalid command")
	return 0

def start_server():
	s.bind((host, port))
	s.listen(5)
	print "Listening on ", port
	while True:
		conn, addr = s.accept()
		print 'Client connected from: ', addr
		size = int(conn.recv(4))
		hello_message = conn.recv(size)
		if hello_message == "Hello":
			conn.send(format(len("Connected"), '04d'))
			conn.send("Connected")
			while True:
				size = int(conn.recv(4))
				cmd = conn.recv(size)
				retval = parse_cmd(cmd, conn, addr)
				if retval == 1:
					break

port = int(raw_input("Enter port number: "))
start_server()