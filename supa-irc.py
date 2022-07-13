VERSION = "0.1.3"

import argparse, socket, threading



#importing lib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
from aiohttp import Payload
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from numpy import array


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
    client_aes = []
    client_priv_serv = []
    client_pub_serv = []
    client_pub_client = []

    def broadcast(message):
        print (message)
        for client in clients_list:
            client.send(message)

    def handle(client):
        while True:
            try:
                message = client.recv(3072)
                ############################
                #receive ENCRYPT [ message ] - DECRYPT using AES KEY - check SIGN using public.key.client - check HASHE of message
                ############################
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
            client.send('NICK'.encode('ascii'))
            nickname = client.recv(1024).decode('ascii')
            clients_nick.append(nickname)
            clients_list.append(client)
            print("Nickname is {}".format(nickname))
            broadcast("{} joined!".format(nickname).encode('ascii'))
            client.send('Connected to server!'.encode('ascii'))

            thread = threading.Thread(target=handle, args=(client,))
            thread.start()

    def main():
        while True:
            client, address = server.accept()
            ############################
            #generate AES and RSA keys
            AES_key = get_random_bytes(32)
            pprivate_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
            pprivate_key = pprivate_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
            private_key = serialization.load_pem_private_key(pprivate_key,password=None,backend=default_backend())
            public_key = private_key.public_key()
            public_key_plain = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            public_key = serialization.load_pem_public_key(public_key_plain,backend=default_backend())
            ############################
            #send RSA public.key.server
            payload = 'INIT- '+str(public_key_plain)
            client.send(str(payload).encode())
            print(payload, "\n\nWAS SEND\n\n")
            ########################################################
            #receive ENCRYPT [ nickname and public.key.client ] - DECRYPT using private.key.server
            mmm =client.recv(4096).decode()
            print(mmm)
            ############################
            #send ENCRYPT [ AES KEY using public.key.client ] and SIGN using private.key.server 
            ############################
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
    def init():
        message = client.recv(1024).decode()
        public_key_plain = message[6:][2:]
        public_key_plain = public_key_plain[:-1]
        public_key_plain = (public_key_plain).replace("\\n", "\n")
        y = ''
        x = public_key_plain.splitlines()[1:-1]
        x = public_key_plain.splitlines()
        for i in x:
            y += i + '\n'
        print(y)
        public_key = serialization.load_pem_public_key(y.encode(), backend=default_backend())
        print(public_key,"\n\nWAS RECEIVE\n\n")
        print("\n\nGENERATING RSA LOCAL KEYS\n\n")
        Lpprivate_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
        Lpprivate_key = Lpprivate_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
        Lprivate_key = serialization.load_pem_private_key(Lpprivate_key,password=None,backend=default_backend())
        Lpublic_key = Lprivate_key.public_key()
        Lpublic_key_plain = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
        print("\n\n         LOCAL PUBLIC KEY PLAIN\n\n", Lpublic_key_plain,"\n\n")
        Lpublic_key = serialization.load_pem_public_key(Lpublic_key_plain ,backend=default_backend())
        print("\n\nENCRYPTING SHIT\n\n")
        encrypted = public_key.encrypt(str(Lpublic_key).encode(),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        print(encrypted)
        client.send(str(encrypted).encode())
        
    init()
    client.send(nickname.encode())


    def crypt(message):
        print("")
    def decrypt(message):
        print("")

    def receive():
        while True:
            try:
                message = client.recv(1024).decode('ascii')
                print(message)
                print(message[:4])
                if message == 'NICK':
                    client.send(nickname.encode('ascii'))
                # elif message[:4] == 'INIT':
                #     #generate RSA keys
                #     local_private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
                #     local_public_key = local_private_key.public_key()
                #     public_key = serialization.load_pem_public_key(
                #                     message[6:],
                #                     backend=default_backend()
                #                 )
                #     print(public_key)
                #     #send ENCRYPT [ nickname and public.key.client ] using public.key.serv
                #     payload = 3
                #     client.send(payload.encode())
                #     #receive ENCRYPT [ AES KEY ] check SIGN using public.key.serv
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
    
