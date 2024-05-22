from http.server import BaseHTTPRequestHandler, HTTPServer

class MyHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/hello':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Hello')
        elif self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><head><title>Python Server</title></head>')
            self.wfile.write(b'<body><p>This is a Python server.</p>')
        else:
            self.send_error(404, 'Not Found')

def main():
    PORT = 8082
    server_address = ('', PORT)

    try:
        httpd = HTTPServer(server_address, MyHTTPRequestHandler)
        print(f"Server started on port {PORT}")
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received, exiting.")
        httpd.server_close()

if __name__ == '__main__':
    main()
