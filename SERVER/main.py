from http.server import HTTPServer, SimpleHTTPRequestHandler

HOST = 'localhost'
PORT = 8000

def run():
    server_address = (HOST, PORT)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    print(f"Serving files at http://{HOST}:{PORT}")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
