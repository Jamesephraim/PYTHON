import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote

HOST = 'localhost'
PORT = 8000
FILES_DIR = 'files'  # Folder to list and serve

os.makedirs(FILES_DIR, exist_ok=True)

class DashboardHandler(BaseHTTPRequestHandler):
    def log_request_info(self):
        print(f"\n[REQUEST] {self.command} {self.path}")

    def list_files_html(self):
        # List files with links
        files = os.listdir(FILES_DIR)
        files.sort()

        # Generate HTML for file list
        items = ""
        for f in files:
            safe_name = f.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            link = f"/files/{safe_name}"
            items += f'<li><a href="{link}">{safe_name}</a></li>\n'

        return items

    def do_GET(self):
        self.log_request_info()

        if self.path == '/':

            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>File Dashboard</title>
<style>
  body {{
    font-family: Arial, sans-serif;
    margin: 40px auto;
    max-width: 800px;
    background: #f4f7f6;
    color: #333;
  }}
  h1 {{
    text-align: center;
    color: #4CAF50;
  }}
  ul {{
    list-style: none;
    padding: 0;
  }}
  li {{
    margin: 8px 0;
    padding: 8px;
    background: #fff;
    border-radius: 5px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    transition: background 0.3s ease;
  }}
  li:hover {{
    background: #e8f5e9;
  }}
  a {{
    text-decoration: none;
    color: #2196F3;
  }}
  a:hover {{
    text-decoration: underline;
  }}
</style>
</head>
<body>
<h1>Local Files Dashboard</h1>
<p>Files in <code>{FILES_DIR}</code> directory:</p>
<ul>
{self.list_files_html()}
</ul>
</body>
</html>
"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))

        elif self.path.startswith('/files/'):
            # Serve file from FILES_DIR
            filename = unquote(self.path[len('/files/'):])  # Decode URL
            safe_filename = os.path.basename(filename)  # Prevent directory traversal
            filepath = os.path.join(FILES_DIR, safe_filename)

            if os.path.isfile(filepath):
                try:
                    with open(filepath, 'rb') as f:
                        self.send_response(200)
                        self.send_header("Content-Type", "application/octet-stream")
                        self.send_header("Content-Disposition", f'attachment; filename="{safe_filename}"')
                        self.end_headers()
                        self.wfile.write(f.read())
                except Exception as e:
                    self.send_error(500, f"Error reading file: {e}")
            else:
                self.send_error(404, "File not found")

        else:
            self.send_error(404, "Page not found")

def run():
    print(f"Serving dashboard at http://{HOST}:{PORT}")
    server = HTTPServer((HOST, PORT), DashboardHandler)
    server.serve_forever()

if __name__ == '__main__':
    run()
