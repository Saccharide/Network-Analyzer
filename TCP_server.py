import socket

def Main():
	host = "127.0.0.1"
	port = 8080

	s = socket.socket()
	s.bind((host,port))

	s.listen(1)
	connection, addr = s.accept()
	print "Connection from : " + str(addr)
	while True:
		data = connection.recv(1024)
		if not data:
			break
		data = str(data)
		print "Message from client: " + data
		
	connection.close()

if __name__ == '__main__':
	Main()
