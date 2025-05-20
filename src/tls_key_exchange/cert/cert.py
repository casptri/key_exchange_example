from pathlib import Path
import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def gen_private_key():
    """
    openssl genrsa -aes256 -out ca.key 4096
    """
    key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend(),
            )
    return key

def gen_csr(key):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bern"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Bern"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "example.local"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "dev@example.com"),
    ])).add_extension(
            #x509.BasicConstraints(ca=False, path_length=None),
            x509.SubjectAlternativeName([
                # Describe what sites we want this certificate for.
                x509.DNSName("localhost"),
            ]),
            critical=False,
        # Sign the CSR with our private key.
    ).sign(key, hashes.SHA256())
    return csr

def gen_cert_ca(key):
    issuer = x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bern"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Bern"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "tke.example.local"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "dev@example.com"),
        ])

    cert = x509.CertificateBuilder().subject_name(
                issuer
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            ).sign(key, hashes.SHA256(), default_backend())
    return cert

def gen_cert_csr(csr, ca_cert, ca_key):
    cert = x509.CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                ca_cert.subject
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            ).sign(ca_key, hashes.SHA256(), default_backend())
    return cert


def save_key(file_path, key):
    with file_path.open('wb') as fd:
        fd.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            #encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8')),
            encryption_algorithm=serialization.NoEncryption(),
        ))



def save_cert(file_path, cert):
    with file_path.open('wb') as fd:
        fd.write(cert.public_bytes(serialization.Encoding.PEM))

def load_key(file_path):
    with file_path.open("rb") as fd:
        key = serialization.load_pem_private_key(
            fd.read(),
            password=None,
            backend=default_backend()
        )
    return key

def load_cert(file_path):
    with file_path.open("rb") as fd:
        cert_data = fd.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    return cert


if __name__ == "__main__":
    ca_key =  gen_private_key()
    server_key =  gen_private_key()
    client_key =  gen_private_key()

    ca_cert = gen_cert_ca(ca_key)

    server_csr = gen_csr(server_key)
    client_csr = gen_csr(client_key)

    server_cert = gen_cert_csr(server_csr, ca_cert, ca_key)
    client_cert = gen_cert_csr(client_csr, ca_cert, ca_key)


    ca_key_path = Path() / "ca.key"
    with ca_key_path.open('wb') as fd:
        fd.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            #encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8')),
            encryption_algorithm=serialization.NoEncryption(),
        ))
    server_key_path = Path() / "server.key"
    with server_key_path.open('wb') as fd:
        fd.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            #encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8')),
            encryption_algorithm=serialization.NoEncryption(),
        ))
    client_key_path = Path() / "client.key"
    with client_key_path.open('wb') as fd:
        fd.write(client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            #encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8')),
            encryption_algorithm=serialization.NoEncryption(),
        ))

    ca_cert_path = Path() / "ca.crt"
    with ca_cert_path.open('wb') as fd:
        fd.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    server_cert_path = Path() / "server.crt"
    with server_cert_path.open('wb') as fd:
        fd.write(server_cert.public_bytes(serialization.Encoding.PEM))
    client_cert_path = Path() / "client.crt"
    with client_cert_path.open('wb') as fd:
        fd.write(client_cert.public_bytes(serialization.Encoding.PEM))

