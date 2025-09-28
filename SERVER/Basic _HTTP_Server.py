

from http.server import HTTPServer, BaseHTTPRequestHandler



host='127.0.0.1'
port=7777

#
# \
#

class NeuralHTTP(BaseHTTPRequestHandler):


    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()
        link='/home/ubentu/Desktop/My Project/HTTP-FTP/httpserver.py'
        self.wfile.write(bytes(f"<a href='/home/ubentu/Desktop/My Project/HTTP-FTP/httpserver.py'>Link</a>Basic Http Server Using Python Programming language","utf-8"))
        #self.wfile.write(bytes("</h1></body></html>","utf-8"))



server=HTTPServer((host,port),NeuralHTTP)
print("[+] Server has been Started ....")
server.serve_forever()
server.server_close()
print("[-] Server Stopped...")
    
        
