import argparse, socket, threading



#importing lib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


#color console
W = '\033[0m'
R = '\033[31m' 
G = '\033[32m' 
O = '\033[33m' 
B = '\033[34m' 
P = '\033[35m' 
C = '\033[36m' 
GR = '\033[37m'































################################################
################### SERVER #####################
def serving(host,port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    clients_list = []
    clients_nick = []

    def broadcast(message):
        print (message)
        for client in clients_list:
            client.send(message)

    def handle(client):
        while True:
            try:
                message = client.recv(3072)
                #receive ENCRYPT [ message ] - DECRYPT using AES KEY - check SIGN using public.key.client - check HASHE of message
                broadcast(message)
                print ("\nbroadcoasted !!!\n----------------")
            except:
                index = clients_list.index(client)
                clients_list.remove(client)
                client.close()
                nck = clients_nick[index]
                broadcast(f"{nck.encode()}")
                clients_nick.remove(nck)
                break

    def main():
        while True:
            client, address = server.accept()
            print("Connected with {}".format(str(address)))
            #generate AES and RSA keys
            #send RSA public.key.server
            client.send('NICK'.encode('ascii'))
            #receive ENCRYPT [ nickname and public.key.client ] - DECRYPT using private.key.server
            nickname = client.recv(1024).decode('ascii')
            clients_nick.append(nickname)
            clients_list.append(client)
            #send ENCRYPT [ AES KEY using public.key.client ] and SIGN using private.key.server 
            print("Nickname is {}".format(nickname))
            broadcast("{} joined!".format(nickname).encode('ascii'))
            client.send('Connected to server!'.encode('ascii'))

            thread = threading.Thread(target=handle, args=(client,))
            thread.start()

    def main():
        while True:
            client, address = server.accept()
            print (f"\nNew user connected at {address}")
            clients_list.append(client)
            print (clients_list)
            thread = threading.Thread(target=handle, args=(client,))
            thread.start()

    print (f'\nServer is running on {host} using port {port}...')
    main()


























################################################
################### CLIENT #####################
def clienting(host,port,nickname):
    if nickname == None:
        nickname = input("Nickname >: ")
        print(nickname)
    else:
        print(nickname)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect ((host, port))
    client.send(nickname.encode())
    def receive():
        while True:
            try:
                message = client.recv(1024).decode('ascii')
                if message == 'NICK':
                    client.send(nickname.encode('ascii'))
                    #generate RSA keys
                    #send ENCRYPT [ nickname and public.key.client ] using public.key.serv
                    #receive ENCRYPT [ AES KEY ] check SIGN using public.key.serv
                else:
                    print(message)
            except:
                print("An error occured!")
                client.close()
                break
    def write():
        while True:
            message = R+f'{nickname}'+B+' : '+W+'{}'.format(input(R'>'+B+': '+W))
            print(message)
            if "QUIT" in message:
                client.close()
                exit(-1)
            #send ENCRYPT [ message ] using AES key and SIGN using private.key.client - HASHE of message
            client.send(message.encode('ascii'))

    receive_thread = threading.Thread(target=receive)
    receive_thread.start()

    write_thread = threading.Thread(target=write)
    write_thread.start()


















parser = argparse.ArgumentParser()
parser.add_argument( "--server", "-s",  help="Host supa-irc server.", action="store_true")   
parser.add_argument( "--client", "-c", help="Connect to supa-irc server", action="store_true") 
parser.add_argument( "--address", "-a", help="Addrees to use.")   
parser.add_argument( "--port", "-p", help="Port to use.")   
parser.add_argument( "--nick", "-n", help="Choose nickname")   
# parser.add_argument( "--options", "-o", help="making comment for remember how to use parser")   
args = parser.parse_args()

if args.server:
    serving(args.address,int(args.port))

if args.client:
    clienting(args.address,int(args.port),args.nick)
    
