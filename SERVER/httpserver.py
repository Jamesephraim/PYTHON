

from http.server import HTTPServer, BaseHTTPRequestHandler



host='127.0.0.1'
port=7787

class NeuralHTTP(BaseHTTPRequestHandler):


    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()

        self.wfile.write(bytes('<html><body><h1>Hello World !</h1> </body></html',"utf-8"))



server=HTTPServer((host,port),NeuralHTTP)

print("[+] Server has been Started ....")
print('[+] Using This Link ',f'http://{host}:{port}')

server.serve_forever()
server.server_close()

print("[-] Server Stopped...")
    
        
