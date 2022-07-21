VERSION =   "0.2.1"


import argparse, socket, threading, time, base64, os
from inspect import signature
from random import *




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
    client_aes = []
    client_priv_serv = []   
    client_pub_serv = []
    client_pub_client = []

    def crypt(message, client):
        index = clients_list.index(client)
        AES_key = client_aes[index]

        l = 16 - (len(message) % 16)
        message = ("\r"*(l+16)).encode() + message
        
        cipher = AES.new(
            AES_key, 
            AES.MODE_CBC
        )
        
        message = cipher.encrypt(                
            pad(message,                 
            AES.block_size)      
        )

        return message


    def decrypt(message, client):

        message = bytes(str(message).encode())

        print("FLAG 1")

        index = clients_list.index(client)
        AES_key = client_aes[index]

        print("FLAG 2")

        iv = message [:16]
        encrypted_data = message [16:]
    
        print("FLAG 3")
        input("aaaaaa")

        cipher = AES.new(
            AES_key, AES.MODE_CBC, 
            iv=iv
        )

        print("FLAG 4")

        message = unpad(
            cipher.decrypt(encrypted_data), 
            AES.block_size
        )

        print("FLAG 5")

        message = message.decode().replace('\r','')

        print("mseea",message)

        return message
        

    def sign(message, client):        
        index = clients_list.index(client)
        private_key = client_priv_serv[index]

        digest = hashes.Hash(hashes.SHA256())
        digest.update(message)
        hash = digest.finalize()

        signature = private_key.sign(
            hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return signature, hash


    def check_sign(message,signature, client):
        index = clients_list.index(client)
        public_key_client = client_pub_client[index]

        digest = hashes.Hash(hashes.SHA256())
        digest.update(message)
        hash = digest.finalize()

        try:
            verif = public_key_client.verify(
                signature,
                hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except:
            verif = False
            message = R + 'NON LEGIT // ' + W
        
        return verif


    def send(message,signature,client):
        client.send(message)
        client.send(signature)


    def handle(client):
        while True:
            try:
                message = client.recv(8192)
                print("RECEIVED")
                if len(message) == 0:
                    print("ZEROWED")
                    index = clients_list.index(client)
                    client.close()

                else:
                    print(message)
                    message = decrypt(message,client)
                    print(message)
                    message = bytes(str(message).encode())

                    print('éééé',message)

                    if message[:4] == 'MESS':
                        message = client.recv(8192)
                        message = decrypt(message,client)
                        signature = client.recv(8192)
                        signature = decrypt(signature,client)
                        verif = check_sign(message,signature,client)
                        
                        if verif == False:
                            verif = "hash check - " + R + "FAILED" + W + " - ❌"
                        else:
                            verif = "hash check - " + G + "NO ERROR" + W + " - ✅"

                        for client in clients_list:
                            signature, hash = sign(message,client)
                            message = crypt(message,client)
                            send(message,signature,client)

                        print(f"""
{B}╭╴{O}New message Received{W}
{B}│{W}{verif}
{B}│{W}hash received : {P}{str(hash[:-1])[-6:]}{W}
{B}╰──{W}{message}""")

            except:
                client.close()
                index = clients_list.index(client)
                clients_list.remove(client)
                clients_nick.remove(clients_nick[index])
                client_aes.remove(client_aes[index])
                client_priv_serv.remove(client_priv_serv[index])
                client_pub_serv.remove(client_pub_serv[index])
                client_pub_client.remove(client_pub_client[index])
                break

    def main():
        while True:
            client, address = server.accept()
            AES_key = get_random_bytes(32)

            private_key_plain = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
            private_key_plain = private_key_plain.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
            private_key = serialization.load_pem_private_key(private_key_plain,password=None,backend=default_backend())
            public_key = private_key.public_key()
            public_key_plain = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            public_key = serialization.load_pem_public_key(public_key_plain,backend=default_backend())
   
            payload = str(public_key_plain)
            client.send(str(payload).encode())

            message =client.recv(8192).decode()
            nickname = message
            time.sleep(0.2)
            message =client.recv(8192)
            
            message_half_1 = private_key.decrypt(message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            message_half_1 = message_half_1[2:-1]
            print(message_half_1,"\nHalf-1 GOOD\n")

            time.sleep(0.2)
            message =client.recv(8192)
            
            message_half_2 = private_key.decrypt(message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            message_half_2 = message_half_2[2:-1]

            message_complete = message_half_1 + message_half_2
            message_complete = message_complete.decode().replace("\\n","\n")
            pre_public_key_client = message_complete.encode()
            public_key_client = serialization.load_pem_public_key(pre_public_key_client ,backend=default_backend())
            
            encrypted = public_key_client.encrypt((AES_key),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            
            encrypted = base64.b64encode(encrypted)
            print("\n\nAES_KEY {\n",public_key_client, "\n}       WAS SUCCESSFULLY ENCRYPTED\n\n")
            
            client.send(str(encrypted).encode())
            print (f"\nNew user connected at {address}")
            
            clients_nick.append(nickname)
            clients_list.append(client)
            client_aes.append(AES_key)
            client_priv_serv.append(private_key)
            client_pub_serv.append(public_key_plain)
            client_pub_client.append(public_key_client)
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

    message = client.recv(8192).decode()

    public_key_server_plain = message[2:-1]
    public_key_server_plain = (public_key_server_plain).replace("\\n", "\n")
    
    pre_public_key_server = ''
    lines = public_key_server_plain.splitlines()[1:-1]
    lines = public_key_server_plain.splitlines()
    
    for i in lines:
        pre_public_key_server += i + '\n'
    
    public_key_server = serialization.load_pem_public_key(
        str(pre_public_key_server).encode(), 
        backend=default_backend()
    )
    print("\n\npublic_key_server {\n",public_key_server, "\n}       WAS RECIEVED\n\n")

    private_key_plain = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=4096, 
        backend=default_backend()
    )

    private_key_plain = private_key_plain.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    private_key = serialization.load_pem_private_key(
        private_key_plain,
        password=None,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    public_key_plain = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("\n\nLOCAL public_key_server {\n",public_key_plain, "\n}       WAS GENERATED\n\n")
    
    public_key = serialization.load_pem_public_key(
        public_key_plain ,
        backend=default_backend()
    )
            
    client.send(str(nickname).encode())
    time.sleep(0.1)

    message_half_1 = public_key_plain[:len(public_key_plain)//2]
    print(message_half_1,"\nHalf-1 GOOD\n")

    encrypted = public_key_server.encrypt(str(message_half_1).encode(),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))

    client.send((encrypted))
    time.sleep(0.1)
    message_half_2 = public_key_plain[len(public_key_plain)//2:]
    print(message_half_2,"\nHalf-2 GOOD\n")
    encrypted = public_key_server.encrypt(str(message_half_2).encode(),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    client.send((encrypted))

    message = client.recv(8192).decode()
    message = base64.b64decode(message[2:-1])
    message = private_key.decrypt(message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    
    AES_key = message
    print("\n\nAES_KEY {\n",AES_key, "\n}\n\n")
    

    print("\n\nINITIALISATION SUCCESSFULL\n\n")



    def sign(message):        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message)
        hash = digest.finalize()

        signature = private_key.sign(
            hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return signature, hash


    def check_sign(message,signature):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message)
        hash = digest.finalize()

        try:
            verif = public_key.verify(
                signature,
                hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except:
            verif = False
            message = R + 'NON LEGIT // ' + W
        
        return verif


    def crypt(message):       
        l = 16 - (len(message) % 16)
        message = ("\r"*(l+16)).encode() + message
        
        cipher = AES.new(
            AES_key, 
            AES.MODE_CBC
        )
        
        message = cipher.encrypt(
            pad(message, 
            AES.block_size)
        )

        time.sleep(0.1)

        iv = message [:16]
        encrypted_data = message [16:]

        cipher = AES.new(
            AES_key, AES.MODE_CBC, 
            iv=iv
        )

        message = unpad(
            cipher.decrypt(encrypted_data), 
            AES.block_size
        )
        message = message.decode().replace('\r','')
        
        print("clear\n",message)

        return encrypted


    def decrypt(message):
        iv = message [:16]
        encrypted_data = message [16:]

        cipher = AES.new(
            AES_key, AES.MODE_CBC, 
            iv=iv
        )

        message = unpad(
            cipher.decrypt(encrypted_data), 
            AES.block_size
        )
        message = message.decode().replace('\r','')
        
        return message

    def receive():
        while True:
            try:
                message = client.recv(8192)
                signature = client.recv(8192)
                message = decrypt(message)
                verif, hash = check_sign(message,signature)
                if verif == False:
                    verif = "hash check - " + R + "FAILED" + W + " - ❌"
                else:
                    verif = "hash check - " + G + "NO ERROR" + W + " - ✅"

                print(f"""
{B}╭╴{O}New message Received{W}
{B}│{W}{verif}
{B}│{W}hash received : {P}{str(hash[:-1])[-6:]}{W}
{B}╰──{W}{message}""")

            except:
                print("An error occured!")
                client.close()
                break

    def write():
        message = R+f'{nickname}'+B+' : '+W+'{}'.format(input(R'>'+B+': '+W))
        if "QUIT" in message:
            client.close()
            exit(-1)
        elif message[-4:] == "FILE":
            inpute = input(G + "Enter the file path you want to send : " + W)

            with open (inpute, 'rb') as f_inpute:
                message = f_inpute.read()
            
                infoA = "FILE"
                iB = []
                iba = inpute.split('/')
                for a in iba:
                    iB.append(a)
                infoB = iB[len(iB)-1]
                infoC = ( len(message) // 8100 ) + 1
                info = f"{infoA}{infoB};;;{infoC}"
                
                n = 8100
                chunks = [message[i:i+n] for i in range(0, len(message), n)]
                c = 0

                client.send(info)

                for i in range(len(chunks)):
                    i = bytes(str(i).encode())
                    signature = sign(i)
                    message = crypt(i)

                    client.send(message)
                    client.send(signature)

                    print(f"part {c} sended")
                    c += 1
        else:
            info = crypt(bytes(str(f"MESS;;;{nickname}").encode()))
            print("AAwwAA\n",info)
            aaa  = decrypt(info)

            
            signature =crypt(bytes(str(sign(bytes(str(message).encode()))).encode()))
            message = crypt(bytes(str(message).encode()))
            

            client.send(info)
            time.sleep(0.1)

            

            client.send(message)
            time.sleep(0.1)
            client.send(signature)



    
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
    
