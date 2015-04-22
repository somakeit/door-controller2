import SimpleHTTPServer
import SocketServer
from StringIO import StringIO
import sys, json

DATAFILE_NAME = 'testserver.json'

try:
    datafile = open(DATAFILE_NAME, 'r')
except IOError:
    data = {}
else:
    data = json.loads(''.join(datafile.readlines()))
    datafile.close()

def update_dict(dicta, dictb):
    for key in dictb:
        if not key in dicta:
            dicta[key] = dictb[key]
        elif isinstance(dictb[key], dict):
            dicta[key] = update_dict(dicta[key], dictb[key])
        else:
            dicta[key] = dictb[key]
    return(dicta);
    
class MyWankyHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def send_head(self):
        global data
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        retdata = json.dumps(data)
        self.send_header('Content-Length', str(len(retdata)))
        self.end_headers()
        return StringIO(retdata)

    def do_POST(self):
        global data
        data = update_dict(data, json.loads(self.rfile.read(int(self.headers.getheader('content-length', 0)))))
        datafile = open(DATAFILE_NAME, 'w')
        datafile.write(json.dumps(data, sort_keys=True, indent=4, separators=(',', ': ')))
        datafile.close()
        self.send_response(200)
        self.end_headers()

if sys.argv[1:]:
    PORT = int(sys.argv[1])
else:
    PORT = 8000

#Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
Handler = MyWankyHandler

httpd = SocketServer.TCPServer(("", PORT), Handler)

print "serving at port", PORT
httpd.serve_forever()

print 'lol'
print data.readlines()
