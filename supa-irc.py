VERSION =   "0.1.12"


import argparse, socket, threading, time, base64



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

    def broadcast(message,client):
        # TO REVIEW FROM HERE
        print("\nIN : ", message,len(message))
        index = clients_list.index(client)
        AES_key = client_aes[index]
        public_key_client = client_pub_client[index]

        print(index,AES_key)
        
        
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
        
        signature = client.recv(8192)

        digest = hashes.Hash(hashes.SHA256())
        digest.update(message.encode())
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


        for client in clients_list:
            index = clients_list.index(client)
            AES_key = client_aes[index]
            private_key = client_priv_serv[index]

            message = bytes(str(message).encode())
            
            # Sign using hash of message
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

        
            client.send(message)
            # input("PAUSE")
            time.sleep(0.1)
            client.send(signature)
            
            iv = message [:16]
            encrypted_data = message [16:]
            cipher = AES.new(AES_key, AES.MODE_CBC, iv=iv)
            message = unpad(cipher.decrypt(encrypted_data), AES.block_size)

            # message = base64.b64decode(message)
            message = message.decode().replace('\r','')

            
            if verif == False:
                verif = "hash check - " + R + "FAILED" + W + " - ❌"
            else:
                verif = "hash check - " + G + "NO ERROR" + W + " - ✅"
            print(f"""
{B}╭╴{O}New message Received{W}
{B}│{W}{verif}
{B}│{W}hash received : {P}{str(hash[:-1])[-6:]}{W}
{B}╰──{W}{message}""")

        print ("\nbroadcoasted !!!\n----------------")

    def handle(client):
        while True:
            try:
                message = client.recv(8192)
                if len(message) == 0:
                    print("ZEROWED")
                    index = clients_list.index(client)
                    client.close()

                else:
                    print("\nMessage = ",message)
                    broadcast(message, client)
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

            # Accept connection
            client, address = server.accept()
            
            # Generate AES
            AES_key = get_random_bytes(32)
            
            # Generating RSA key
            private_key_plain = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
            private_key_plain = private_key_plain.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
            private_key = serialization.load_pem_private_key(private_key_plain,password=None,backend=default_backend())
            public_key = private_key.public_key()
            public_key_plain = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            public_key = serialization.load_pem_public_key(public_key_plain,backend=default_backend())
            
            # Send RSA public_key_plain
            payload = str(public_key_plain)
            client.send(str(payload).encode())
            
            # Receive nickname
            message =client.recv(8192).decode()
            nickname = message
            time.sleep(0.2)
            
            # Receive first half of public_key_client
            message =client.recv(8192)
            
            # Decrypt mesage using private_key
            message_half_1 = private_key.decrypt(message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            message_half_1 = message_half_1[2:-1]
            print(message_half_1,"\nHalf-1 GOOD\n")

            time.sleep(0.2)
            
            # Receive second half of public_key_client
            message =client.recv(8192)
            
            # Decrypt message using private_key
            message_half_2 = private_key.decrypt(message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            message_half_2 = message_half_2[2:-1]

            # Encapsulate both part
            message_complete = message_half_1 + message_half_2
            message_complete = message_complete.decode().replace("\\n","\n")
            pre_public_key_client = message_complete.encode()
            public_key_client = serialization.load_pem_public_key(pre_public_key_client ,backend=default_backend())
            
            # Encrypt AESkey using publickeylient
            encrypted = public_key_client.encrypt((AES_key),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            
            # Encode encrypted using base64
            encrypted = base64.b64encode(encrypted)
            print("\n\nAES_KEY {\n",public_key_client, "\n}       WAS SUCCESSFULLY ENCRYPTED\n\n")
            
            # Send encrypted
            client.send(str(encrypted).encode())
            print (f"\nNew user connected at {address}")
            
            #appending all list with client info
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
    
    # Connect to server
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect ((host, port))

    # Receiving RSA public_key_server
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
    
    # Generate RSA keys
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
    
    print("\n\nENCRYPTING SHIT\n\n")
            
    # Send nickname in plain text for fun
    client.send(str(nickname).encode())
    print("\nNick send\n")
    time.sleep(0.1)

    # Create first half of public_key
    message_half_1 = public_key_plain[:len(public_key_plain)//2]
    print(message_half_1,"\nHalf-1 GOOD\n")

    # Encrypt message_half_1 using public_key_server
    encrypted = public_key_server.encrypt(str(message_half_1).encode(),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))

    # Send half 1
    client.send((encrypted))
    time.sleep(0.1)

    # create first half of public_key
    message_half_2 = public_key_plain[len(public_key_plain)//2:]
    print(message_half_2,"\nHalf-2 GOOD\n")

    # Encrypt message_half_1 using public_key_server
    encrypted = public_key_server.encrypt(str(message_half_2).encode(),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    
    # Send half 2
    client.send((encrypted))

    #Receive AES key
    message = client.recv(8192).decode()
    
    # Decode message using base64
    message = base64.b64decode(message[2:-1])
    print("\n\nBase64 encoded string {\n",public_key, "\n}\n\n")

    
    # Decrypt message using private_key
    message = private_key.decrypt(message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    
    # Save devrypted message as AES key
    AES_key = message
    print("\n\nAES_KEY {\n",AES_key, "\n}\n\n")
    

    print("\n\nINITIALISATION SUCCESSFULL\n\n")


    def crypt(message):
        
        # Sign using hash of message
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

    
        client.send(message)
        # input("PAUSE")
        time.sleep(0.1)
        client.send(signature)

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
        
        signature = client.recv(8192)

        digest = hashes.Hash(hashes.SHA256())
        digest.update(message.encode())
        hash = digest.finalize()

        try:
            verif = public_key_server.verify(
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

        return message, verif, hash

    def receive():
        while True:
            try:
                message = client.recv(8192)
                message, verif, hash = decrypt(message)
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
        while True:
            # time.sleep(1)
            message = R+f'{nickname}'+B+' : '+W+'{}'.format(input(R'>'+B+': '+W))
        
            if "QUIT" in message:
                client.close()
                exit(-1)
            message = bytes(str(message).encode())
            message = crypt(message)           
            

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
    
