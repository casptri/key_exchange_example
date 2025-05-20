from flask import Flask, send_from_directory, request, redirect
import os
from pathlib import Path

import string
import secrets

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64


from tls_key_exchange.cert.cert import gen_private_key, save_key, save_cert, gen_csr

up_path = Path("upload")
up_path.mkdir(parents=True, exist_ok=True)
tls_path = Path("tls")
tls_path.mkdir(parents=True, exist_ok=True)
client_key_path = tls_path / "client.key"
client_csr_path = tls_path / "client.csr"
if not client_key_path.exists() or not client_csr_path.exists():
    client_key =  gen_private_key()
    client_csr = gen_csr(client_key)
    save_cert(client_csr_path, client_csr)
    save_key(client_key_path, client_key)

key = Fernet.generate_key()
print(key)

alphabet = string.digits
password = ''.join(secrets.choice(alphabet) for i in range(8))
salt = os.urandom(16)

def generate_key(password: str, salt: bytes) -> bytes:
    """Generate a key from a password and a salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def decrypt_data(data: bytes, password: str, salt: bytes) -> bytes:
    key = generate_key(password, salt)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(data)
    return decrypted

app = Flask(__name__)

@app.route('/')
def hello_world():
    return "Hello World"

@app.route('/csr')
def get_csr():
    csr_path = client_csr_path.parent
    print(csr_path)
    return send_from_directory(str(csr_path),"client.csr", as_attachment=True) 

@app.route('/salt', methods=['GET'])
def get_salt():
    print(f"===== {password} =====")
    salt64 = base64.urlsafe_b64encode(salt)
    return salt64


@app.route('/add', methods=['POST'])
def add_connection():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
    file = request.files['file']
    file.save(os.path.join("upload", file.filename))
    enc_path = Path("upload") / file.filename
    dec_name = Path(file.filename).stem + ".crt" 
    dec_path = Path("upload") / dec_name
    with enc_path.open('rb') as fd:
        enc_data = fd.read()
    dec_data = decrypt_data(enc_data, password, salt)
    with dec_path.open('wb') as fd:
        fd.write(dec_data)
    return "ok"

if __name__ == '__main__':
    app.run(host="localhost", port=5080)
