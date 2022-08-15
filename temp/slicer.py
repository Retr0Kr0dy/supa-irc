##  Just a temp script.
#   
#   While i'm implementing file sending
#   you got to manually split and 
#   unsplit your file before and
#   after encryption.

import os



file_to_slice = input("Enter the name of file to slice : ")
size = input("Enter the size of each chunk (default is 1,000,000,000) : ")
if len(size) == 0:
    size = 1000000000
else:
    size = int(size)
fnl = file_to_slice.split("/")
file_name = fnl[len(fnl)-1]


print(file_to_slice,size,file_name)

with open(file_to_slice, 'rb') as rf:
    full_file = rf.read()

n = size
chunks = [full_file[i:i+n] for i in range(0, len(full_file), n)]

print(len(full_file))
print(len(chunks))

try:
    os.makedirs(f"./{file_name}")
except:
    print("folder already exists")

tick = 1

for c in chunks:
    with open(f"./{file_name}/{file_name}.part.{tick}", 'wb') as wf:
        wf.write(c)
    tick += 1
