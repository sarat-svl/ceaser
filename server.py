#!/usr/bin/python3           # This is server.py file
import random
import pickle
import socket
import hashlib

#importing necessary functions to perform diffee_hellman key exchange
from diffee_hellman import *

# import thread module
from _thread import *
import threading

def readfile():
    return f.read(1024)

print_lock = threading.Lock()
#Password file declaration
password_file = {}

# create a socket object
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Assign port number to server
port = 9999

# bind to the port
#Give host as empty string so that server can listen
#to requests coming from other networks
serversocket.bind(('', port))

# queue up to 5 requests
serversocket.listen(5)

print("Socket is listening........")

while True:

	clientsocket,addr = serversocket.accept()

	print_lock.acquire()

	print("Got a connection from %s" % str(addr))

	data = clientsocket.recv(1024)

	recv_data = pickle.loads(data)

	g = recv_data[0]

	n = recv_data[1]

	A_B = recv_data[2]

	 # Private key of server

	B_pk = random.randint(1,n)

	 # calculate B_A = g^(B_pk) mod n

	B_A = fea(g, B_pk, n)

	clientsocket.send(bytes(str(B_A),'utf8'))

	KB_A = fea(A_B,B_pk,n)

	print("Received from client <g, n, A_B> : ",recv_data)

	print("Final key by server (KB_A) : ",KB_A)

	while True:

		print("------Waiting for credentials-----")

		data = clientsocket.recv(1024)

		enc_credentials = pickle.loads(data)

		#Decryption of cipher plain_text
		dec_credentials = []

		for item in enc_credentials:

		   	dec_credentials.append(ceaser_cipher_decrypt(str(item), KB_A))

		print("Decrypted credentials received from client : ",dec_credentials)

		logged_in = False

		if len(dec_credentials) == 3:

		   Id = dec_credentials[0]

		   Pw = dec_credentials[1]

		   Q_A = dec_credentials[2]

		   #-------------INSERTING DATA INTO PASSWORD FILE-----------

		   # checking if id is present in file

		   if Id in password_file.keys() :

			   status_msg = "UN-SUCCESSFUL"

			   clientsocket.send(status_msg.encode('ascii'))

		   else:

			   salt = random.randint(1,n)

			   concatination = str(Pw)+str(salt)+str(Q_A)

			   hash_value = hashlib.sha1(concatination.encode()).hexdigest()

			   password_file[Id] = {}

			   password_file[Id]['salt'] = salt

			   password_file[Id]['hashed_password'] = hash_value

			   password_file[Id]['prime'] = Q_A

			   status_msg = "SUCCESSFUL"

			   clientsocket.send(status_msg.encode('ascii'))

		else:

		   Id = dec_credentials[0]

		   Pw = dec_credentials[1]

		   if Id in password_file.keys():

		    	salt_A = password_file[Id]['salt']

		    	Q_A = password_file[Id]['prime']

		    	concatination = str(Pw)+str(salt_A)+str(Q_A)

		    	computed_hash = hashlib.sha1(concatination.encode()).hexdigest()

		    	if computed_hash == password_file[Id]['hashed_password']:

		    		status_msg = "SUCCESSFUL"

		    		clientsocket.send(status_msg.encode('ascii'))

		    		data = clientsocket.recv(1024)

		    		file_contents = pickle.loads(data)

		    		Id = file_contents[0]

		    		file = file_contents[1]

		    		file_name = './Files/'+file

		    		try:

		    			f = open(file_name,'r')

		    			for piece in iter(lambda: f.read(1024),''):

		    				clientsocket.send(piece.encode('ascii'))

		    				service_done = [file, "SUCCESSFUL"]

		    				data = pickle.dumps(service_done)

		    				clientsocket.send(data)

		    			f.close()

		    			break	 

		    		except FileNotFoundError:

		    			clientsocket.send('Not-found'.encode('ascii'))

		    			reply = [file,"UN-SUCCESSFUL"]

		    			data = pickle.dumps(reply)

		    			clientsocket.send(data)

		    	else:

		    		status_msg = "UN-SUCCESSFUL"

		    		clientsocket.send(status_msg.encode('ascii'))

		recv_conn = clientsocket.recv(1024)

		conn = recv_conn.decode('utf8')

		print("status : ",conn)

		if conn == 'y':

			continue

		else:

			print_lock.release()

			print("clinet "+str(addr)+" released")

			break

clientsocket.close()
