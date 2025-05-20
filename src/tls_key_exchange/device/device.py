import requests
import base64
import click
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from tls_key_exchange.cert.cert import gen_private_key, save_key, gen_cert_ca, save_cert, gen_csr, load_cert, load_key, gen_cert_csr

new_ca = False
ca_path = Path("ca")
ca_path.mkdir(parents=True, exist_ok=True)
ca_cert_path = ca_path / "ca.crt"
ca_key_path = ca_path / "ca.key"
if not ca_key_path.exists() or not ca_cert_path.exists():
    ca_key = gen_private_key()
    ca_cert = gen_cert_ca(ca_key)
    save_key(ca_key_path, ca_key)
    save_cert(ca_cert_path, ca_cert)
    new_ca = True

tls_path = Path("tls")
tls_path.mkdir(parents=True, exist_ok=True)
server_cert_path = tls_path / "server.crt"
server_key_path  = tls_path / "server.key"

ca_key = load_key(ca_key_path)
ca_cert = load_cert(ca_cert_path)
if not server_cert_path.exists() or not server_key_path.exists() or new_ca:
    server_key =  gen_private_key()
    server_csr = gen_csr(server_key)
    server_cert = gen_cert_csr(server_csr, ca_cert, ca_key)
    save_key(server_key_path, server_key)
    save_cert(server_cert_path, server_cert)


def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_data(data: bytes, password: str, salt: bytes) -> bytes:
    key = generate_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    return encrypted

base_url = "http://localhost:5080/"
csr_url = base_url + "csr"

response = requests.get(csr_url)

print(response.content)
csr_data = response.content
client_csr = x509.load_pem_x509_csr(csr_data, default_backend())
client_cert = gen_cert_csr(client_csr, ca_cert, ca_key)
client_cert_data = client_cert.public_bytes(serialization.Encoding.PEM)
ca_cert_data = ca_cert.public_bytes(serialization.Encoding.PEM)

salt_url = base_url + "salt"

response = requests.get(salt_url)

print(response.text)
salt = base64.urlsafe_b64decode(response.text)
print(salt)

value = click.prompt('Enter random number', type=str)
print(value, type(value))

enc_data = encrypt_data(client_cert_data, value, salt)
with open("./client.enc", 'wb') as fd:
    fd.write(enc_data)

upload_url = base_url + "add"
with open("./client.enc", 'rb') as fd:
    f = {'file': fd}
    response = requests.post(upload_url, files=f)
print(response.text)

enc_data = encrypt_data(ca_cert_data, value, salt)
with open("./ca.enc", 'wb') as fd:
    fd.write(enc_data)

upload_url = base_url + "add"
with open("./ca.enc", 'rb') as fd:
    f = {'file': fd}
    response = requests.post(upload_url, files=f)
print(response.text)
