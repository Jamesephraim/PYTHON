import socket
 

c=socket.socket()

sys=socket.gethostname()
host= input('[+] Enter Server Host Ip :')            #'127.0.0.1'#socket.gethostname()
port= int(input('[+] Enter Server Port:'))

print("\n\n-------------------------")
print("[+] Username :",sys)
print("[+] IP :",host)
print("[+] PORT :",port)
print('---------------------------\n\n')
c.connect((host,port))
myname=input("[+] Enter Your Name:")
c.send(bytes(myname,'utf-8'))
name=c.recv(1024).decode()
while True:
     
    data=input(f"[+] {myname} :")
    
    c.send(bytes(data,"utf-8"))
    print(f'[+] {name} :',c.recv(1024).decode())

c.close()


 
