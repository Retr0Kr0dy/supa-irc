VERSION =   "0.2.2"


import argparse, socket, threading, time, base64, os
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
from sympy import content

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
        # message = bytes(str(message).encode())
        
        index = clients_list.index(client)
        AES_key = client_aes[index]

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

        print(message,type(message))
        print(signature,type(signature))
        print(hash,type(hash))
        

        return signature, hash


    def check_sign(message,signature, client):        
        index = clients_list.index(client)
        public_key_client = client_pub_client[index]


        message = bytes(str(message).encode())

        signature = bytes(str(signature).encode()[2:-1])
        signature = signature.decode('unicode-escape').encode('ISO-8859-1')
        
        
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
            verif = True
        except:
            verif = False
            message = R + 'NON LEGIT // ' + W
        print(verif)
        return verif, hash


    def send(message,signature,client):
        client.send(message)
        time.sleep(0.2)
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
                    message = decrypt(message,client)
                    # message = bytes(str(message).encode())
                    
                    print(message)
                    print(message[:4])

                    if message[:4] == 'MESS':
                        message = client.recv(8192)
                        message = decrypt(message,client)
                        signature = client.recv(8192)
                        signature = decrypt(signature,client)
                        verif, hash = check_sign(message,signature,client)
                        
                        if verif == False:
                            verif = "hash check - " + R + "FAILED" + W + " - ❌"
                        else:
                            verif = "hash check - " + G + "NO ERROR" + W + " - ✅"

                        print(f"""
{B}╭╴{O}New message Received{W}
{B}│{W}{verif}
{B}│{W}hash received : {P}{str(hash[:-1])[-6:]}{W}
{B}╰──{W}{message}""")

                        for client in clients_list:
                            print(message)
                            signature, hash = sign(bytes(str(message).encode()),client)
                            print(signature,type(signature))
                            signature = crypt(bytes(str(signature).encode()),client)
                            
                            message = crypt(bytes(str(message).encode()),client)
                            send(message,signature,client)
                        

                    if message[:4] == 'FILE':
                        message = message[4:].split(';;;')
                        name = message[0]
                        lenght = message[1]
                        t_port = int(message[2])
                        signature = client.recv(8192)
                        message = b''
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            print(s)
                            s.bind((host, t_port))
                            print(f"host on {host}:{t_port}")
                            s.listen()
                            conn, addr = s.accept()
                            message = b''
                            with conn:
                                print(f"Connected by {addr}")
                                while True:
                                    aa = conn.recv(1024)
                                    if not aa:
                                        break
                                    message = message + aa
                                    print(str((len(message) * 100) / int(lenght))[:6], ' %')
                                    
                            time.sleep(0.1)
                            s.close()
                      
                        index = clients_list.index(client)
                        AES_key = client_aes[index]

                        iv = message [:16]
                        encrypted_data = message [16:]

                        cipher = AES.new(AES_key, AES.MODE_CBC,iv=iv)
                        message = unpad(cipher.decrypt(encrypted_data),AES.block_size)

                        message = message.replace('AAAA'.encode(),''.encode())
                        
                        signature = decrypt(signature,client)
                        verif, hash = check_sign(message,signature,client)
                        
                        if verif == False:
                            verif = "hash check - " + R + "FAILED" + W + " - ❌"
                        else:
                            verif = "hash check - " + G + "NO ERROR" + W + " - ✅"

                        file = "file/" + name
                        with open(file, 'wb') as wf:
                            wf.write(message)

                        print("ALL GOOD")
    
                    elif message[:4] == 'GETF':
                        import glob
                        content = glob.glob("file/*")
                        lay = ""
                        for i in content:
                            lay = lay + i[5:] + "\n" 
                        print("\n\n",lay)
                        lay = crypt(bytes(str(lay).encode()),client)
                        print("crypted")
                        print(lay)
                        client.send(lay)
                        print("check")
                        m = client.recv(8192)
                        m = decrypt(bytes(str(m).encode()),client)
                        print(m)
                        m = content[int(m)]
                        try:
                            with open(m, 'rb') as r:
                                message = r.read()
                                print(message[:200])
                                lll = len(message)
                                infoA = "FILE"
                                iB = []
                                iba = r.split('/')
                                for a in iba:
                                    iB.append(a)
                                infoB = iB[len(iB)-1]
                                infoC = len(message)
                                infoD = 9878
                                info = f"{infoA}{infoB};;;{infoC};;;{infoD}"
                                sigi = sign(bytes(str(info).encode()),client)
                                sigm = sign(bytes(str(message).encode()),client)

                                info = crypt(bytes(str(info).encode()),client)
                                sigi = crypt(bytes(str(sigi).encode()),client)



                                l = 16 - (len(message) % 16)
                                message = ("AAAA"*(l+16)).encode() + message       
                            
                                cipher = AES.new(AES_key,AES.MODE_CBC)
                                message = cipher.encrypt(pad(message,AES.block_size))

                                sigm = crypt(bytes(str(sigm).encode()))


                                client.send(info)
                                time.sleep(0.1)
                                client.send(sigm)
                                time.sleep(0.5)

                                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                                    s.connect((host, infoD))
                                    print(f"send to {host}:{infoD}")
                                    s.sendall(message)
                                    s.close()

                                print(lll)
                                print("END")
                                time.sleep(0.1)
                        except:
                            print("File sending failed")

                            

                    

                   

                        


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
        message = bytes(str(message).encode())

        signature = bytes(str(signature).encode()[2:-1])
        signature = signature.decode('unicode-escape').encode('ISO-8859-1')
        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message)
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
            verif = True
        except:
            verif = False
        
        return verif, hash


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
        
        return message


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

                if len(message) == 0:
                    print("ZEROWED")
                    client.close()
                    break


                time.sleep(0.1)
                signature = client.recv(8192)
                message = decrypt(message)
               
                signature = decrypt(signature)
                
              
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
                print(f">{B}:{W}",end=" ")

            except:
                print("An error occured!")
                client.close()
                break

    def write():
        while True:
            message = R+f'{nickname}'+B+' : '+W+'{}'.format(input('>'+B+': '+W))
            if "QUIT" in message:
                client.close()
                exit(-1)

                #  NOT WORKING
            ##############################################
            elif message[-4:] == "FILE":
                def takefile():
                        try:
                            inpute = input(G + "Enter the file path you want to send : " + W)
                            return inpute
                        except:
                            print(R"FAILED - Can't open file\n")
                            takefile
                inpute = takefile()
                print(inpute)       
                with open (inpute, 'rb') as f_inpute:
                    message = f_inpute.read()
                    print(message[:200])
                    lll = len(message)
                    infoA = "FILE"
                    iB = []
                    iba = inpute.split('/')
                    for a in iba:
                        iB.append(a)
                    infoB = iB[len(iB)-1]
                    infoC = len(message)
                    infoD = 9878
                    info = f"{infoA}{infoB};;;{infoC};;;{infoD}"
                    sigi = sign(bytes(str(info).encode()))
                    sigm = sign(bytes(str(message).encode()))

                    info = crypt(bytes(str(info).encode()))
                    sigi = crypt(bytes(str(sigi).encode()))



                    l = 16 - (len(message) % 16)
                    message = ("AAAA"*(l+16)).encode() + message       
                
                    cipher = AES.new(AES_key,AES.MODE_CBC)
                    message = cipher.encrypt(pad(message,AES.block_size))

                    sigm = crypt(bytes(str(sigm).encode()))


                    client.send(info)
                    time.sleep(0.1)
                    client.send(sigm)
                    time.sleep(0.5)

                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.connect((host, infoD))
                        print(f"send to {host}:{infoD}")
                        s.sendall(message)
                        s.close()

                    print(lll)
                    print("END")
                    time.sleep(0.1)

            elif message[-4:] == "GETF":
                message = crypt(bytes(str(message[-4:]).encode()))
                client.send(message)
                print("sendet")

                lay = decrypt(client.recv(8192))
                print("Content of server ;\n")
                ch = []
                for i in lay.splitlines():
                    ch.append(i)
                    print(f'[{len(ch)-1}] - {ch[len(ch)-1]}')
                c = input("\nEnter the indx of the file you want to download : ")
                c = crypt(bytes(str(c).encode()))
                client.send(c)
                

                
                message = client.recv(8192).decode()
                print(message)
                message = message[4:].split(';;;')
                print(message)
                name = message[0]
                lenght = message[1]
                t_port = int(message[2])
                signature = client.recv(8192)
                message = b''
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    print(s)
                    s.bind((host, t_port))
                    print(f"host on {host}:{t_port}")
                    s.listen()
                    conn, addr = s.accept()
                    message = b''
                    with conn:
                        print(f"Connected by {addr}")
                        while True:
                            aa = conn.recv(1024)
                            if not aa:
                                break
                            message = message + aa
                            print(str((len(message) * 100) / int(lenght))[:6], ' %')
                            
                    time.sleep(0.1)
                    s.close()
                
                iv = message [:16]
                encrypted_data = message [16:]

                cipher = AES.new(AES_key, AES.MODE_CBC,iv=iv)
                message = unpad(cipher.decrypt(encrypted_data),AES.block_size)

                message = message.replace('AAAA'.encode(),''.encode())
                
                signature = decrypt(signature)
                verif, hash = check_sign(message,signature)
                
                if verif == False:
                    verif = "hash check - " + R + "FAILED" + W + " - ❌"
                else:
                    verif = "hash check - " + G + "NO ERROR" + W + " - ✅"

                file = name
                with open(file, 'wb') as wf:
                    wf.write(message)

                print("ALL GOOD")
                
               
            ##############################################
            else:                
                info = crypt(bytes(str(f"MESS;;;{nickname}").encode()))

                sig,hsh = sign(bytes(str(message).encode()))
                signature =crypt(bytes(str(sig).encode()))
                message = crypt(bytes(str(message).encode()))

                sss = decrypt(signature)
        
                print(sss)
                verif = check_sign(decrypt(message),sss)

                if verif == False:
                    verif = "hash check - " + R + "FAILED" + W + " - ❌"
                else:
                    verif = "hash check - " + G + "NO ERROR" + W + " - ✅"
                print(verif)
                
                
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
    
