from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer


FTP_PORT = randint(2121,3232)
FTP_USER = binascii.b2a_base64(os.urandom(15))[:-2]
FTP_PASSWORD = binascii.b2a_base64(os.urandom(15))[:-2]
FTP_DIRECTORY = "./file/"


def main():
    authorizer = DummyAuthorizer()
    authorizer.add_user(FTP_USER, FTP_PASSWORD, FTP_DIRECTORY, perm='elradfmw')
    handler = FTPHandler
    handler.authorizer = authorizer
    handler.banner = "Best server arn't in russia"

    address = ('', FTP_PORT)
    server = FTPServer(address, handler)

    server.max_cons = 2
    server.max_cons_per_ip = 2

    server.serve_forever()


if __name__ == '__main__':
    main()
