import argparse, socket, threading

def serving():
    host = '127.0.0.1'
    port = 55555    
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
            print (f"\nNew user connected at {address}")
            clients_list.append(client)
            print (clients_list)
            thread = threading.Thread(target=handle, args=(client,))
            thread.start()

    print (f'\nServer is running on {host} using port {port}...')
    main()

def clienting():
    host = '127.0.0.1'
    port = 55555
    nickname = input("")

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect ((host, port))
    client.send(nickname.encode())
    def receive():
        while True:
            try:
                message = client.recv(1024).decode('ascii')
                if message == 'NICK':
                    client.send(nickname.encode('ascii'))
                else:
                    print(message)
            except:
                print("An error occured!")
                client.close()
                break
    def write():
        while True:
            message = '[red]{}[blue] : [white]{}'.format(nickname, input(''))
            client.send(message.encode('ascii'))

    receive_thread = threading.Thread(target=receive)
    receive_thread.start()

    write_thread = threading.Thread(target=write)
    write_thread.start()
