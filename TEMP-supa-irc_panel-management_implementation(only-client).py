VERSION = "0.1.10"

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

        print(index,AES_key)
        
        iv = message [:16]
        encrypted_data = message [16:]
        
        print("DECRYPT")
        
        cipher = AES.new(
            AES_key, 
            AES.MODE_CBC, 
            iv=iv
        )

        message = unpad(
            cipher.decrypt(encrypted_data), 
            AES.block_size
        )

        message = message.decode().replace('\r','')
        
        print(message)
        
        # message = decrypt(message,client)
        print("DECRYPTED")
        for client in clients_list:
            print("client = ",client)
            index = clients_list.index(client)
            AES_key = client_aes[index]
            message = bytes(str(message).encode())
            # #send ENCRYPT [ message ] using AES key and SIGN using private.key.client - HASHE of message
            # message = crypt(message)            
            l = 16 - (len(message) % 16)
            message = ("\r"*(l+16)).encode() + message
            # message = base64.b64encode(message)
            cipher = AES.new(AES_key, AES.MODE_CBC)
            message = cipher.encrypt(pad(message, AES.block_size))
            print("\n\nMESSAGE HA BEEN ENCRYPTED\n\n")
            print(message)
            # message = encrypt(message,client)
            client.send(message)

            print("SENF")
            iv = message [:16]
            encrypted_data = message [16:]
            print("DECRYPT")
            cipher = AES.new(AES_key, AES.MODE_CBC, iv=iv)
            message = unpad(cipher.decrypt(encrypted_data), AES.block_size)

            # message = base64.b64decode(message)
            message = message.decode().replace('\r','')
            print(message)
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
            print("\n\nPAYLOAD {\n",payload, "\n}       WAS SEND\n\n")
            
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
            print(message_half_2,"\nHalf-1 GOOD\n")

            # Encapsulate both part
            message_complete = message_half_1 + message_half_2
            message_complete = message_complete.decode().replace("\\n","\n")
            print("\n\n         Ok, pause, you just sent Y\n            and now you want to load the key \n")
            pre_public_key_client = message_complete.encode()
            public_key_client = serialization.load_pem_public_key(pre_public_key_client ,backend=default_backend())
            
            # Encrypt AESkey using publickeylient
            encrypted = public_key_client.encrypt((AES_key),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            
            # Encode encrypted using base64
            encrypted = base64.b64encode(encrypted)
            print("\n\nAES_KEY {\n",public_key_client, "\n}       WAS SUCCESSFULLY ENCRYPTED\n\n")
            
            # Send encrypted
            client.send(str(encrypted).encode())
            print("\n\n AES_KEY sent \n\n")
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
                message = decrypt(message)
                return message
            except:
                print("An error occured!")
                client.close()
                break
    
    def write():
        while True:
            time.sleep(1)
            message = R+f'{nickname}'+B+' : '+W+'{}'.format(input(R'>'+B+': '+W))
        
            if "QUIT" in message:
                client.close()
                exit(-1)
            message = bytes(str(message).encode())
            message = crypt(message)

            



    def Layouting():
        from random import randint
        # import time
        from rich import print as rprint
        from rich.layout import Layout
        from rich.panel import Panel
        from rich.live import Live
        from rich.console import Console

            
        layout = Layout()
        message = []
        list = ["fsklfj", "fsfef"]
        ip, port = "192.158.144.263", "25486"
        lmessage = ""
        for i in message:
            lmessage += i + "\n"
        llist = ""
        for i in list:
            llist = i + "[purple] - [white]" + llist
            

        while True:
        
            xxx = randint(100, 999)    
            with Live(layout, refresh_per_second=10000):
                aaa = receive()
                message.append(aaa+"\n")
                lmessage = ""
                for i in message:
                    lmessage = f"\n" + i + "\n" + lmessage

                # time.sleep(0.1)
                list.append(str(xxx))
                llist = ""
                for i in list:
                    llist = i + "[purple] - [white]" + llist
                layout = Layout()
                console = Console()
                layout.split_column(
                    Layout(Panel("XXXX", title="tA1"), name="A1"),
                    Layout(Panel(f"{lmessage}", title="[bold purple]Live Message", title_align="left", subtitle="[bold green]Write your message down here", subtitle_align="left", border_style="yellow"), name="A2"),
                )
                layout["A1"].split_column(
                    Layout(Panel(f"\n[bold yellow]ANNC-CRYPTED-IRC\n[green]Server IP[white] = [magenta]{ip}[yellow]:[magenta]{port}", title="[bold yellow]\nANNC-CRYPTED-IRC", border_style="black"), name="A3"),
                    Layout(Panel("XXXX", title="tA4"), name="A4")
                )
                layout["A4"].split_row(
                    Layout(Panel(f"{llist}", title="[bold purple]Connected Clients", title_align="left", border_style="bold cyan"), name="A6"),
                    Layout(Panel(f"[green]HASHE[white] = [green]{randint(848975316873513542135416876487864867687486,948975316873513542135416876487864867687486)}", title="[bold purple]Server Sercurity Check Var", title_align="left", border_style="bold cyan"), name="A7")
                )

                # aaa = receive()
                # message.append(aaa+"\n")
                # lmessage = ""
                # for i in message:
                #     lmessage = f"\n" + i + "\n" + lmessage

                # time.sleep(0.1)
                # list.append(str(xxx))
                # llist = ""
                # for i in list:
                #     llist = i + "[purple] - [white]" + llist
                rprint(layout)





    layout_thread = threading.Thread(target=Layouting)
    layout_thread.start()

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
    
