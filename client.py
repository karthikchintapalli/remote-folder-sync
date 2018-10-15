import socket                   
import md5
import subprocess

tcp_socket = socket.socket()             
server_ip = ""
server_port = 6000
server_files = []
cur_folder = "./sharedfolder2"

def index_cmd(cmd):
	tcp_socket.send(format(len(cmd), '04d'))
	tcp_socket.send(cmd)
	size = int(tcp_socket.recv(4))
	statusstr = tcp_socket.recv(size)
	status = statusstr.split(' ')
	if status[0] == "Error:":
		print statusstr
	else:
		del server_files[:]
		filecount = tcp_socket.recv(4)
		filecount = int(filecount)
		for i in xrange(0, filecount):
			size = int(tcp_socket.recv(4))
			filename = tcp_socket.recv(size)
			size = int(tcp_socket.recv(4))
			filesize = tcp_socket.recv(size)
			size = int(tcp_socket.recv(4))
			filedate = tcp_socket.recv(size)
			size = int(tcp_socket.recv(4))
			filetype = tcp_socket.recv(size)
			size = int(tcp_socket.recv(4))
			checksum = tcp_socket.recv(size)
			file = {
				"filesize": filesize,
				"timestamp": filedate,
				"filename": filename,
				"filetype": filetype,
				"checksum": checksum
			}
			server_files.append(file)
			print
			print "Name: " + filename
			print "Type: " + filetype
			print "Size: " + filesize
			print "Last modified: " + filedate

def hash_cmd(cmd):
	cmdsplit = cmd.split()
	if len(cmdsplit) >= 2:
		arg = cmdsplit[1]
	tcp_socket.send(format(len(cmd), '04d'))
	tcp_socket.send(cmd)
	size = int(tcp_socket.recv(4))
	statusstr = tcp_socket.recv(size)
	status = statusstr.split(' ')
	if status[0] == "Error:":
		print statusstr
	else:
		if arg == "verify":
			size = int(tcp_socket.recv(4))
			checksum = tcp_socket.recv(size)

			size = int(tcp_socket.recv(4))
			timestamp = tcp_socket.recv(size)

			print "Checksum: " + repr(checksum)
			print "Last Modified: " + timestamp

		elif arg == "checkall":
			filecount = int(tcp_socket.recv(4))
			for i in xrange(0, filecount):
				size = int(tcp_socket.recv(4))
				filename = tcp_socket.recv(size)

				size = int(tcp_socket.recv(4))
				checksum = tcp_socket.recv(size)

				size = int(tcp_socket.recv(4))
				timestamp = tcp_socket.recv(size)

				print
				print "Filename: " + filename
				print "Checksum: " + repr(checksum)
				print "Last Modified: " + timestamp

def download_cmd(cmd):
	tcp_socket.send(format(len(cmd), '04d'))
	tcp_socket.send(cmd)

	size = int(tcp_socket.recv(4))
	statusstr = tcp_socket.recv(size)
	status = statusstr.split(' ')
	if status[0] == "Error:":
		print statusstr
	else:
		cmdsplit = cmd.split()
		arg = cmdsplit[1]
		filename = cmdsplit[2]
		filecontent = ''
		udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		if arg == "udp":
			udp_socket.bind(('', 6100))
			tcp_socket.send(format(6100, '04d'))

		if arg == "tcp":
			size = int(tcp_socket.recv(4))
			checksum = tcp_socket.recv(size)

			size = int(tcp_socket.recv(4))
			permissions = tcp_socket.recv(size)

		else:
			size, addr = udp_socket.recvfrom(4)
			size = int(size)
			checksum, addr = udp_socket.recvfrom(size)

			size, addr = udp_socket.recvfrom(4)
			size = int(size)
			permissions, addr = udp_socket.recvfrom(size)

		while tcp_socket.recv(4) == "Next":
			if arg == "tcp":
				size = int(tcp_socket.recv(4))
				filecontent += tcp_socket.recv(size)
			else:
				size, addr = udp_socket.recvfrom(4)
				size = int(size)
				newcontent, addr = udp_socket.recvfrom(size)
				filecontent += newcontent

		filehash = md5.new()
		filehash.update(filecontent)
		recvchecksum = filehash.digest()
		if recvchecksum == checksum:
			f = open(cur_folder + '/' + filename, 'w+')
			f.write(filecontent)
			f.close()
			udp_socket.close()
			out = subprocess.check_output(["chmod", permissions, cur_folder + '/' + filename])
		else:
			download_cmd(cmd)

def exit_cmd(cmd):
	tcp_socket.send(format(len(cmd), '04d'))
	tcp_socket.send(cmd)

def parse_cmd(cmd):
	cmdsplit = cmd.split()
	if cmdsplit[0] == "index":
		index_cmd(cmd)
	elif cmdsplit[0] == "hash":
		hash_cmd(cmd)
	elif cmdsplit[0] == "download":
		download_cmd(cmd)
	elif cmdsplit[0] == "exit":
		exit_cmd(cmd)
		return 1
	return 0

def start_client():
	tcp_socket.connect((server_ip, server_port))
	tcp_socket.send(format(len("Hello"), '04d'))
	tcp_socket.send("Hello")
	size = int(tcp_socket.recv(4))
	resp = tcp_socket.recv(size)
	if resp == "Connected":
		print "Connected to " + server_ip + ":" + str(server_port)
		while True:
			cmd = raw_input(">>> ")
			retval = parse_cmd(cmd)
			if retval == 1:
				break
	else:
		print resp
	tcp_socket.close()

#server_ip = raw_input("Enter IP address of server: ")
server_port = raw_input("Enter port to connect to: ")
server_port = int(server_port)
start_client()