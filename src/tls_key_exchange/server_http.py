from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl

SERVER_CERTFILE = "device/tls/server.crt"
SERVER_KEYFILE  = "device/tls/server.key"
CA_CERTFILE     = "device/ca/ca.crt"

server_address = ('', 8443)
httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(certfile=SERVER_CERTFILE, keyfile=SERVER_KEYFILE)
ssl_context.load_verify_locations(cafile=CA_CERTFILE)
ssl_context.verify_mode = ssl.CERT_REQUIRED

httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)

httpd.serve_forever()
