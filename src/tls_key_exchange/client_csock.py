import socket
import ssl

# Paths to your certificate and key files
CLIENT_CERTFILE = "app/upload/client.crt"
CLIENT_KEYFILE  = "app/tls/client.key"
CA_CERTFILE     = "app/upload/ca.crt"

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Wrap the socket with SSL
ssl_sock = ssl.wrap_socket(sock,
                           keyfile=CLIENT_KEYFILE,
                           certfile=CLIENT_CERTFILE,
                           ca_certs=CA_CERTFILE,
                           cert_reqs=ssl.CERT_REQUIRED
                           )

print(ssl_sock.context.get_ca_certs())

# Connect to the server
server_address = ('localhost', 10000)
ssl_sock.connect(server_address)

# Send data
message = b'Hello, world!'
print('Sending:', message)
ssl_sock.sendall(message)

# Receive data
data = ssl_sock.recv(16)
print('Received:', data)

# Clean up the connection
ssl_sock.close()
