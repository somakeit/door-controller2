import SimpleHTTPServer
import SocketServer
from StringIO import StringIO

message = 'some JSON here'

class MyWankyHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def send_head(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(message)))
        self.end_headers()
        return StringIO(message)

    def do_POST(self):
        print self.rfile.read(int(self.headers.getheader('content-length', 0)))
        self.send_response(200)
        self.end_headers()

PORT = 8000

#Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
Handler = MyWankyHandler

httpd = SocketServer.TCPServer(("", PORT), Handler)

print "serving at port", PORT
httpd.serve_forever()

print 'lol'
print data.readlines()
