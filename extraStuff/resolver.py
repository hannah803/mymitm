import socket, struct
import SocketServer
PORT = 8888

# Python socket module does not have this constant
SO_ORIGINAL_DST = 80


class Resolver(object):
    def original_addr(self, csock):
		odestdata = csock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
		_, port, a1, a2, a3, a4 = struct.unpack("!HHBBBBxxxxxxxx", odestdata)
		address = "%d.%d.%d.%d" % (a1, a2, a3, a4)
		return address, port



class ServerHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		r = Resolver()
		print r.original_addr(self.request)


class ThreadedServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass
	
if __name__ == "__main__":
	ThreadedServer.allow_reuse_address = True
	ThreadedServer(('', PORT), ServerHandler).serve_forever()
