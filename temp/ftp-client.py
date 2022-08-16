from ftplib import FTP

file = ''
user = ''
password = ''
port = ''
address = ''

ftp = FTP()
ftp.connect(address,port)
ftp.login(user,password)

#get file
handle = open('./'.rstrip("/") + "/" + file.lstrip("/"), 'wb')
ftp.retrbinary('RETR %s' % file, handle.write)

#send file
handle = open('./'.rstrip("/") + "/" + file.lstrip("/"), 'rb')
ftp.storbinary('STOR %s' % file, handle.read)
