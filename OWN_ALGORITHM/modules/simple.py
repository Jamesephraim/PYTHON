from encrypt_decrypt import *

data=input("Enter Text :")
x=encrypt(data)
y=decrypt(x)
print("\nEncrypted Data .......")
for d in x:
    print(d , end="")
print("\nDecrypted Data .......")
for d in y:
    print(d , end="")