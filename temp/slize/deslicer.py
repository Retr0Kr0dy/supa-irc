##  Just a temp script.
#   
#   While i'm implementing file sending
#   you got to manually split and 
#   unsplit your file before and
#   after encryption.

import os



file_to_deslice = input("Enter the name of the folder to deslice : ")

file_list = os.walk(file_to_deslice)
f_list = []
fnl = file_to_deslice.split("/")
file_name = fnl[len(fnl)-2]
print(file_name)

for i,x,v in file_list:
    for i in v:
        f_list.append(i)
f_list = sorted(f_list)

print(f_list)

full_file = [b'']

for f in f_list:
    with open(file_to_deslice+f,'rb') as rb:
        full_file.append(rb.read())

full_file = b''.join(full_file)

try:
    os.makedirs(f"./{file_name}")
except:
    print("folder already exists")


with open(f"./{file_name}/{file_name}", 'wb') as wf:
    wf.write(full_file)
