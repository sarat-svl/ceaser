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

		   Id = str(dec_credentials[0])

		   Pw = str(dec_credentials[1])

		   Q_A = str(dec_credentials[2])

		   #-------------INSERTING DATA INTO PASSWORD FILE-----------

		   # checking if id is present in file

		   if Id in password_file.keys() :

			   status_msg = ceaser_cipher_encrypt("UNSUCCESSFUL", KB_A)

			   clientsocket.send(status_msg.encode('ascii'))

		   else:

			   salt = str(random.randint(1,n))

			   concatination = Pw+salt+Q_A

			   hash_value = hashlib.sha1(concatination.encode()).hexdigest()

			   password_file[Id] = {}

			   password_file[Id]['salt'] = salt

			   password_file[Id]['hashed_password'] = hash_value

			   password_file[Id]['prime'] = Q_A

			   status_msg = ceaser_cipher_encrypt("SUCCESSFUL",KB_A)

			   clientsocket.send(status_msg.encode('ascii'))

		else:

		   Id = str(dec_credentials[0])

		   Pw = str(dec_credentials[1])

		   if Id in password_file.keys():

		    	salt_A = password_file[Id]['salt']

		    	Q_A = password_file[Id]['prime']

		    	concatination = Pw+salt_A+Q_A

		    	computed_hash = hashlib.sha1(concatination.encode()).hexdigest()

		    	if computed_hash == password_file[Id]['hashed_password']:

		    		status_msg = ceaser_cipher_encrypt("SUCCESSFUL",KB_A)

		    		clientsocket.send(status_msg.encode('ascii'))

		    		data = clientsocket.recv(1024)

		    		encrypted_file_contents = pickle.loads(data)

		    		file_contents = []

		    		for item in encrypted_file_contents:

		    			file_contents.append(ceaser_cipher_decrypt(str(item), KB_A))

		    		Id = file_contents[0]

		    		file = file_contents[1]

		    		file_name = './Files/'+file

		    		try:

		    			f = open(file_name,'r')

		    			for piece in iter(lambda: f.read(1024),''):

		    				encrypted_piece = ceaser_cipher_encrypt(str(piece),KB_A)

		    				clientsocket.send(encrypted_piece.encode('ascii'))

		    				service_done = [file, "SUCCESSFUL"]

		    				encrypted_service_done = []

		    				for item in service_done:

		    					encrypted_service_done.append(ceaser_cipher_encrypt(item, KB_A))

		    				data = pickle.dumps(encrypted_service_done)

		    				clientsocket.send(data)

		    			f.close()

		    			break	 

		    		except FileNotFoundError:

		    			print("File not found")

		    			clientsocket.send('Not found'.encode('ascii'))

		    			reply = [file,"UNSUCCESSFUL"]

		    			encrypted_reply = []

		    			for item in reply:

		    				encrypted_reply.append(ceaser_cipher_encrypt(item, KB_A))

		    			data = pickle.dumps(encrypted_reply)

		    			clientsocket.send(data)

		    	else:

		    		status_msg = ceaser_cipher_encrypt("UNSUCCESSFUL", KB_A)

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
