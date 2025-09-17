import socket

s = socket.socket()
host = socket.gethostname()
ip = socket.gethostbyname(host)
port = int(input('[+] Set Port:'))

s.bind((ip, port))
print("\n\n-------------------------")
print("[+] Hostname :", host)
print("[+] IP       :", ip)
print("[+] PORT     :", port)
s.listen(2)

print(f'\n\n[+] Waiting For Connections.... {ip, port}')
c, addr = s.accept()
print('[+] Connected With', addr)

try:
    while True:
        data = c.recv(1024)
        if not data:
            print("\n[!] Client disconnected")
            break
        with open("server_log.txt","a") as Log_data:
            Log_data.write(f"{data.decode()}")
        #print(data.decode(), end="", flush=True)
except Exception as e:
    print(f"\n[!] Error: {e}")
finally:
    c.close()
    s.close()
