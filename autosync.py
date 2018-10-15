import socket
import subprocess
import datetime
import re
import md5
import threading
import sys
import time

class Client:
	def __init__(self, folder, port):
		self.tcp_socket = socket.socket()             
		self.server_ip = ""
		self.server_port = port
		self.server_files = []
		self.cur_folder = folder

	def index_cmd(self, cmd):
		self.tcp_socket.send(format(len(cmd), '04d'))
		self.tcp_socket.send(cmd)
		size = int(self.tcp_socket.recv(4))
		statusstr = self.tcp_socket.recv(size)
		status = statusstr.split(' ')
		if status[0] == "Error:":
			print statusstr
		else:
			new_files = []
			filecount = self.tcp_socket.recv(4)
			filecount = int(filecount)
			for i in xrange(0, filecount):
				size = int(self.tcp_socket.recv(4))
				filename = self.tcp_socket.recv(size)
				size = int(self.tcp_socket.recv(4))
				filesize = self.tcp_socket.recv(size)
				size = int(self.tcp_socket.recv(4))
				filedate = self.tcp_socket.recv(size)
				size = int(self.tcp_socket.recv(4))
				filetype = self.tcp_socket.recv(size)
				size = int(self.tcp_socket.recv(4))
				checksum = self.tcp_socket.recv(size)
				found = 0
				for server_file in self.server_files:
					if server_file["filename"] == filename:
						found = 1
						break
				if found == 0:
					file = {
						"filesize": filesize,
						"timestamp": filedate,
						"filename": filename,
						"filetype": filetype,
						"checksum": checksum
					}
					self.server_files.append(file)
					new_files.append(filename)
			return new_files

	def hash_cmd(self, cmd):
		cmdsplit = cmd.split()
		if len(cmdsplit) >= 2:
			arg = cmdsplit[1]
		self.tcp_socket.send(format(len(cmd), '04d'))
		self.tcp_socket.send(cmd)
		size = int(self.tcp_socket.recv(4))
		statusstr = self.tcp_socket.recv(size)
		status = statusstr.split(' ')
		if status[0] == "Error:":
			print statusstr
		else:
			if arg == "verify":
				size = int(self.tcp_socket.recv(4))
				checksum = self.tcp_socket.recv(size)

				size = int(self.tcp_socket.recv(4))
				timestamp = self.tcp_socket.recv(size)

				print "Checksum: " + repr(checksum)
				print "Last Modified: " + timestamp

			elif arg == "checkall":
				updated_files = []
				filecount = int(self.tcp_socket.recv(4))
				for i in xrange(0, filecount):
					size = int(self.tcp_socket.recv(4))
					filename = self.tcp_socket.recv(size)

					size = int(self.tcp_socket.recv(4))
					checksum = self.tcp_socket.recv(size)

					size = int(self.tcp_socket.recv(4))
					timestamp = self.tcp_socket.recv(size)

					for server_file in self.server_files:
						if server_file["filename"] == filename:
							if server_file["checksum"] != checksum:
								updated_files.append(filename)
							break
				return updated_files

	def download_cmd(self, cmd):
		self.tcp_socket.send(format(len(cmd), '04d'))
		self.tcp_socket.send(cmd)

		size = int(self.tcp_socket.recv(4))
		statusstr = self.tcp_socket.recv(size)
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
				self.tcp_socket.send(format(6100, '04d'))

			if arg == "tcp":
				size = int(self.tcp_socket.recv(4))
				checksum = self.tcp_socket.recv(size)

			else:
				size, addr = udp_socket.recvfrom(4)
				size = int(size)
				checksum, addr = udp_socket.recvfrom(size)

			while self.tcp_socket.recv(4) == "Next":
				if arg == "tcp":
					size = int(self.tcp_socket.recv(4))
					filecontent += self.tcp_socket.recv(size)
				else:
					size, addr = udp_socket.recvfrom(4)
					size = int(size)
					newcontent, addr = udp_socket.recvfrom(size)
					filecontent += newcontent

			filehash = md5.new()
			filehash.update(filecontent)
			recvchecksum = filehash.digest()
			if recvchecksum == checksum:
				f = open(self.cur_folder + '/' + filename, 'w+')
				f.write(filecontent)
				f.close()
				udp_socket.close()
			else:
				self.download_cmd(cmd)

	def exit_cmd(self, cmd):
		self.tcp_socket.send(format(len(cmd), '04d'))
		self.tcp_socket.send(cmd)
		self.tcp_socket.close()

	def start_client(self):
		self.tcp_socket.connect((self.server_ip, self.server_port))
		self.tcp_socket.send(format(len("Hello"), '04d'))
		self.tcp_socket.send("Hello")
		size = int(self.tcp_socket.recv(4))
		resp = self.tcp_socket.recv(size)
		if resp == "Connected":
			pass
		else:
			print resp

class Server():
	def __init__(self, folder, port):
		self.cur_folder = folder
		self.port = port
		self.s = socket.socket()
		self.host = ""
		self.files = []

	def validate(self, date_text):
	    try:
	        date = datetime.datetime.strptime(date_text, "%d/%m/%Y-%H:%M")
	    except ValueError:
	        return False
	    return True

	def get_date(self, filename):
		filedate = subprocess.check_output(["date", "-r", filename, "+%F %T"])
		filedate = filedate.strip('\n')
		filedate = datetime.datetime.strptime(filedate, '%Y-%m-%d %H:%M:%S')	
		return filedate

	def update_file_structure(self):
		del self.files[:]
		lsout = subprocess.check_output(["ls", "-lh", self.cur_folder])
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
				filedate = self.get_date(self.cur_folder + '/' + filename)
				filesize = line[4]
				filehash = md5.new()
				f = open(self.cur_folder + '/' + filename,'r')
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
					"checksum": checksum
				}
				self.files.append(file)

	def index_cmd(self, cmd, conn, addr):
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
					if self.validate(cmd[2]):
						d1 = datetime.datetime.strptime(cmd[2], '%d/%m/%Y-%H:%M')
					else:
						conn.send(format(len("Error: Invalid date format"), '04d'))
						conn.send("Error: Invalid date format")
						return
					if self.validate(cmd[3]):
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
		self.update_file_structure()
		filecount = 0
		for file in self.files:
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

		for file in self.files:
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

	def hash_cmd(self, cmd, conn, addr):
		self.update_file_structure()
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
					for file in self.files:
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
			conn.send(format(len(self.files), '04d'))
			for file in self.files:
				checksum = str(file["checksum"])
				timestamp = str(file["timestamp"])
				filename = str(file["filename"])
				conn.send(format(len(filename), '04d'))
				conn.send(filename)
				conn.send(format(len(checksum), '04d'))
				conn.send(checksum)
				conn.send(format(len(timestamp), '04d'))
				conn.send(timestamp)

	def download_cmd(self, cmd, conn, addr):
		self.update_file_structure()
		found = 0
		index = 0
		filename = ''
		length = len(cmd)
		if length == 3:
			if cmd[1] == "tcp" or cmd[1] == "udp":
				filename = cmd[2]
				for file in self.files:
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

		for file in self.files:
			if (file["filename"] == filename and file["filetype"] == "File"):
				if conn_type == "tcp":
					conn.send(format(len(str(file["checksum"])), '04d'))
					conn.send(str(file["checksum"]))

				else:
					udp_s.sendto(format(len(str(file["checksum"])), '04d'), (client_ip, new_port))
					udp_s.sendto(str(file["checksum"]), (client_ip, new_port))

				f = open(self.cur_folder + '/' + filename,'r')
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
				

	def parse_cmd(self, cmd, conn, addr):
		if not cmd:
			return 0
		cmd = cmd.split()
		if cmd[0] == "exit":
			return 1
		elif cmd[0] == "download":
			self.download_cmd(cmd, conn, addr)
		elif cmd[0] == "hash":
			self.hash_cmd(cmd, conn, addr)
		elif cmd[0] == "index":
			self.index_cmd(cmd, conn, addr)
		else:
			conn.send(format(len("Error: Invalid command"), '04d'))
			conn.send("Error: Invalid command")
		return 0

	def start_server(self):
		self.s.bind((self.host, self.port))
		self.s.listen(5)
		print "Listening on ", self.port
		conn, addr = self.s.accept()
		print 'Client connected from: ', addr
		size = int(conn.recv(4))
		hello_message = conn.recv(size)
		if hello_message == "Hello":
			conn.send(format(len("Connected"), '04d'))
			conn.send("Connected")
			while True:
				size = int(conn.recv(4))
				cmd = conn.recv(size)
				retval = self.parse_cmd(cmd, conn, addr)
				if retval == 1:
					break

class myThread (threading.Thread):
	def __init__(self, threadID, folder, port):
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.folder = folder
		self.port = port
	def run(self):
		sync_files(self.threadID, self.folder, self.port)

def sync_files(threadID, folder, port):
	if threadID == 1:
		server = Server(folder, port)
		server.start_server()
	elif threadID == 2:
		client = Client(folder, port)
		client.start_client()
		new_files = client.index_cmd("index longlist")
		for new_file in new_files:
			client.download_cmd("download tcp " + new_file)
		updated_files = client.hash_cmd("hash checkall")
		for updated_file in updated_files:
			client.download_cmd("download tcp " + updated_file)
		client.exit_cmd("exit")

while True:
	threads = []
	thread1 = myThread(1, "./sharedfolder1", int(sys.argv[1]))
	thread2 = myThread(2, "./sharedfolder2", int(sys.argv[1]))
	threads.append(thread1)
	threads.append(thread2)
	thread1.start()
	thread2.start()

	for t in threads:
		t.join()

	threads = []
	thread1 = myThread(1, "./sharedfolder2", int(sys.argv[2]))
	thread2 = myThread(2, "./sharedfolder1", int(sys.argv[2]))
	threads.append(thread1)
	threads.append(thread2)
	thread1.start()
	thread2.start()

	for t in threads:
		t.join()
	print "Syncing Complete"
	time.sleep(60)
