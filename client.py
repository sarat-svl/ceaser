#!/usr/bin/python3           # This is client.py file
import sys
import random
import pickle
from diffee_hellman import *
import socket

# create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# get local machine name
#host = sys.argv[0]
host = '127.0.0.1'
port = 9999

# connection to hostname on the port.
s.connect((host, port))

#------------------DIFFEE HELLMAN KEY EXCHANFE PROCESS----------------

# Returns prime number and its primitive root

g,n = Diffee()

#Private key generation

A_pk = random.randint(1,n)

# Performs g^e mod n

A_B = fea(g, A_pk, n)

# Receive no more than 1024 bytes

to_server = [g,n,A_B]

#Formatting data to sent to server

data = pickle.dumps(to_server)

s.send(data)

print("<g n Ya> sent to server")

data = s.recv(1024)

# Received g^(ser_pr_key) mod n

B_A = int(data.decode('utf8'))

print("Received key from server : ",B_A)

#Calculating client side shared key using key sent by server

KA_B = fea(B_A, A_pk, n)

print("Final key by client (KA_B) : ",KA_B)


#-----------------LOGIN CREATION PROCESS-------------------

def login_create():

    ID = int(input("Enter Id : "))

    PWA = input("Enter password (max 10 characters) : ")

    #If password length is greator than 10, ask user to give input less than or equal to 10 characters

    while(len(PWA)>10):

        PWA = input("Please give password of lenth max 10 characters : ")

    #Generate a random prime number

    Q_A = generate_prime_number(32)

    print("Your randomly generated prime number : ",Q_A)

    #Encryption of ID password and prime number using ceaser cipher

    credentials = [ID,PWA,Q_A]

    print("-------Encrypting the given credentials-------")

    enc_credentials = []

    for item in credentials:
        enc_credentials.append(ceaser_cipher_encrypt(str(item), KA_B))

    #Send credentials to server

    data = pickle.dumps(enc_credentials)

    s.send(data)

    print("Encrypted credentials have been sent to server : ",enc_credentials)

    encrypted_status_msg = s.recv(1024)

    status_msg = encrypted_status_msg.decode('ascii')

    status_msg = ceaser_cipher_decrypt(status_msg, KA_B)

    print("---------------STATUS---------------")
    print(status_msg)

#----------- LOGIN PROCESS------------------

def login():

    ID = int(input("Enter Id : "))

    PWA = input("Enter password (max 10 characters) : ")

    #If password length is greator than 10, ask user to give input less than or equal to 10 characters

    while(len(PWA)>10):

        PWA = input("Please give password of lenth max 10 characters : ")

    #Encryption of ID password and prime number using ceaser cipher

    credentials = [ID,PWA]

    print("-------Encrypting the given credentials-------")

    enc_credentials = []

    for item in credentials:
        enc_credentials.append(ceaser_cipher_encrypt(str(item), KA_B))

    #Send credentials to server

    data = pickle.dumps(enc_credentials)

    s.send(data)

    print("Encrypted credentials have been sent to server")

    encrypted_status_msg = s.recv(1024)

    status_msg = encrypted_status_msg.decode('ascii')

    status_msg = ceaser_cipher_decrypt(status_msg, KA_B)

    print("---------------STATUS---------------")
    
    print(status_msg)

    if(status_msg == "SUCCESSFUL"):

        file_name = input("Enter file name : ")

        file_contents = [ID, file_name]

        encrypted_file_contents = []

        for item in file_contents:

            encrypted_file_contents.append(ceaser_cipher_encrypt(str(item), KA_B))

        data = pickle.dumps(encrypted_file_contents)

        s.send(data)

        file_data = ''

        while(1):

            recv_text = s.recv(1024)

            file_data = recv_text.decode('ascii')

            file_data = ceaser_cipher_decrypt(file_data, KA_B) 

            recv_data = s.recv(1024)

            try:

                encrypted_recv_service_done = pickle.loads(recv_data)

                recv_service_done = []

                for item in encrypted_recv_service_done:

                    recv_service_done.append(ceaser_cipher_decrypt(str(item), KA_B))

                print("< File - Status > ",recv_service_done[0],recv_service_done[1])

                if recv_service_done[1] == "SUCCESSFUL":
                    
                    new_file = open('client-'+ str(host)+'.txt','w')
                    
                    new_file.write(file_data)
                    
                    new_file.close()

                else:
                    
                    break

            except EOFError:

                break

            

print(" 1. Login create ")

print(" 2. Login ")

while True:
    option = int(input("Enter choice : "))

    if option == 1:

        login_create()

    else:

        login()

    conn = input("Continue to use server (y or n) : ")

    s.send(conn.encode('utf8').strip())

    if conn == 'y':

        continue

    else:

        break

s.close()
