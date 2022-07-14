VERSION = "0.1.6"

import argparse, socket, threading, time  



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

    def broadcast(message,client):
        def decrypt(message,client):
            index = clients_list.index(client)
            AES_key = client_aes[index]
            iv = message [:16]
            encrypted_data = message [16:]
            cipher = AES.new(AES_key, AES.MODE_CBC, iv=iv)
            message = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            print("\n\nDECRYOTED for\n\n",clients_nick[index])
            return message
        def encrypt(message,client):
            index = clients_list.index(client)
            AES_key = client_aes[index]
            cipher = AES.new(AES_key, AES.MODE_CBC)
            message = cipher.encrypt(pad(message, AES.block_size))
            print()
            return message
        print (message)
        for client in clients_list:
            client.send(encrypt(decrypt(message,client),client))

    def handle(client):
        while True:
            try:
                message = client.recv(8192)
                ############################
                #receive ENCRYPT [ message ] - DECRYPT using AES KEY - check SIGN using public.key.client - check HASHE of message
                ############################
                broadcast(message, client)
                print ("\nbroadcoasted !!!\n----------------")
            except:
                index = clients_list.index(client)
                clients_list.remove(client)
                client.close()
                nck = clients_nick[index]
                clients_nick.remove(nck)
                break

    # def main():
    #     while True:
    #         client, address = server.accept()
    #         print("Connected with {}".format(str(address)))
    #         client.send('NICK'.encode('ascii'))
    #         nickname = client.recv(1024).decode('ascii')
    #         clients_nick.append(nickname)
    #         clients_list.append(client)
    #         print("Nickname is {}".format(nickname))
    #         broadcast("{} joined!".format(nickname).encode('ascii'))
    #         client.send('Connected to server!'.encode('ascii'))

    #         thread = threading.Thread(target=handle, args=(client,))
    #         thread.start()

    def main():
        while True:
            #accept connection
            client, address = server.accept()
            ############################
            #generate AES
            AES_key = get_random_bytes(32)
            #generating RSA key
            pprivate_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
            pprivate_key = pprivate_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
            private_key = serialization.load_pem_private_key(pprivate_key,password=None,backend=default_backend())
            public_key = private_key.public_key()
            public_key_plain = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            public_key = serialization.load_pem_public_key(public_key_plain,backend=default_backend())
            ############################
            #send RSA public.key.server
            payload = str(public_key_plain)
            # payload = 'INIT- '+str(public_key_plain)
            client.send(str(payload).encode())
            print(payload, "\n\nWAS SEND\n\n")
            ########################################################
            #receive ENCRYPT nickname and publickeyclient DECRYPT using privatekeyserv
            mmm =client.recv(8192).decode()
            nickname = mmm
            time.sleep(0.2)
            mmm =client.recv(8192)
            #decrypt mmm using privatekeyserver
            mmm1 = private_key.decrypt(mmm,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            print("D#######")
            print(mmm1)
            Dpk1 = mmm1[2:-1]
            time.sleep(0.2)
            mmm =client.recv(8192)
            #decrypt mmm using privatekeyserver
            mmm2 = private_key.decrypt(mmm,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            print("D#######")
            print(mmm2)
            Dpk2 = mmm2[2:-1]
            mmm = Dpk1 + Dpk2
            mmm = mmm.decode().replace("\\n","\n")
            y = ''
            x = mmm.splitlines()[1:-1]
            x = mmm.splitlines()
            for i in x:
                y += i + '\n'
            print(y)
            print("\n\n         Ok, pause, you just sent Y\n            and now you want to load the key \n")
            mmm = mmm.encode()
            print(mmm)
            d_public_key = serialization.load_pem_public_key(mmm ,backend=default_backend())
            print("D#######\n\n     Decrypted so ut's giid fir now\n")
            print(mmm)
            #encrypt AESkey using publickeylient
            print("MMMMMMMMMMM")
            encrypted = d_public_key.encrypt(str(AES_key).encode(),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            print(encrypted)
            print("\n\n             Encrypted Successfully\n")
            client.send(str(encrypted).encode())
            print("\n\n AES key send \n\n")
            # s = str('\n')+(str(AES_key).encode()
            ############################
            #send ENCRYPT  AES KEY using public.key.client ] and SIGN using private.key.server 
            ############################
            print (f"\nNew user connected at {address}")
            clients_nick.append(nickname)
            clients_list.append(client)
            client_aes.append(AES_key)
            client_priv_serv.append(private_key)
            client_pub_serv.append(public_key_plain)
            client_pub_client.append(d_public_key)
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
    #receiving RSA public.key.server
    message = client.recv(8192).decode()
    # AES_key = message.splitlin
    # print("\n\nAES\n",AES_key,'\nEND\n\n')
    # public_key_plain = message[6:][2:]
    public_key_plain = message[2:-1]
    public_key_plain = (public_key_plain).replace("\\n", "\n")
    y = ''
    x = public_key_plain.splitlines()[1:-1]
    x = public_key_plain.splitlines()
    for i in x:
        y += i + '\n'
    print(y)
    public_key = serialization.load_pem_public_key(str(y).encode(), backend=default_backend())
    print(public_key,"\n\nWAS RECEIVE\n\n")
    ############################################
    #Generate RSA keys
    Lpprivate_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    Lpprivate_key = Lpprivate_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
    Lprivate_key = serialization.load_pem_private_key(Lpprivate_key,password=None,backend=default_backend())
    Lpublic_key = Lprivate_key.public_key()
    print(Lpublic_key)
    Lpublic_key_plain = Lpublic_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    print("\n\n         LOCAL PUBLIC KEY PLAIN\n\n", Lpublic_key_plain,"\n\n")
    Lpublic_key = serialization.load_pem_public_key(Lpublic_key_plain ,backend=default_backend())
    print("\n\nENCRYPTING SHIT\n\n")
            
    ##########################################
    #Encrypt public.key.client using public.key.server

    #Send encrypted public.key.client and nickname
    client.send(str(nickname).encode())
    print("nick send")
    time.sleep(0.1)

    Lp_k_p_1 = Lpublic_key_plain[:len(Lpublic_key_plain)//2]
    print(Lp_k_p_1,"GOOD")

    encrypted = public_key.encrypt(str(Lp_k_p_1).encode(),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    client.send((encrypted))

    time.sleep(0.1)

    Lp_k_p_2 = Lpublic_key_plain[len(Lpublic_key_plain)//2:]
    print(Lp_k_p_2,"GOOD")

    encrypted = public_key.encrypt(str(Lp_k_p_2).encode(),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    client.send((encrypted))


    print("pub key send")
    #Receive AES key
    mmm = client.recv(8192)[2:-1]
    print(mmm)
    mmm.replace('\\','\'')
    print(mmm)
    print("\nDECRYPT MEESSAGE\n")
    AES_key = Lprivate_key.decrypt(mmm,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    print("FONOSHEDDDD")


    def crypt(message):
        cipher = AES.new(AES_key, AES.MODE_CBC)
        message = cipher.encrypt(pad(message, AES.block_size))
        print("\n\nMESSAGE HA BEEN ENCRYPTED\n\n")
        return encrypted

    def decrypt(message):
        iv = message [:16]
        encrypted_data = message [16:]
        cipher = AES.new(AES_key, AES.MODE_CBC, iv=iv)
        message = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        print("\n\nMESSAGE HA BEEN DECRYPTED\n\n")
        return message

    def receive():
        while True:
            try:
                message = client.recv(8192).decode()
                message = decrypt(message)
                print(message)
                print(message[:4])
                if message == 'NICK':
                    client.send(nickname.encode())
                else:
                    print(decrypt(message))
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
            client.send(crypt(message).encode())

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
    
