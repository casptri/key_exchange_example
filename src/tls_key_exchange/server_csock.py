import socket
import ssl

# Paths to your certificate and key files
SERVER_CERTFILE = "device/tls/server.crt"
SERVER_KEYFILE  = "device/tls/server.key"
CA_CERTFILE     = "device/ca/ca.crt"

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Wrap the socket with SSL
ssl_sock = ssl.wrap_socket(sock,
                           keyfile=SERVER_KEYFILE,
                           certfile=SERVER_CERTFILE,
                           server_side=True,
                           ca_certs=CA_CERTFILE,
                           cert_reqs=ssl.CERT_REQUIRED
                           )

print("----------")
print(ssl_sock.context.get_ca_certs())
print("----------")

# Bind the socket to a specific address and port
server_address = ('localhost', 10000)
ssl_sock.bind(server_address)

# Listen for incoming connections
ssl_sock.listen(1)


while True:
    print('Waiting for a connection...')
    connection, client_address = ssl_sock.accept()
    try:
        print('Connection from:', client_address)

        # Receive the data in small chunks and retransmit it
        while True:
            data = connection.recv(16)
            print('Received:', data)
            if data:
                print('Sending data back to the client')
                connection.sendall(data)
            else:
                print('No more data from:', client_address)
                break
    finally:
        # Clean up the connection
        connection.close()
