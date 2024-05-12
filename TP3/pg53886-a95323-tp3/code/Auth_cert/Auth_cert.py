from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509

def load_data(file, password=None):
    with open(f"Auth_cert/{file}.p12", "rb") as file:
        p12_data = file.read()
    private_key, certificate, _ = pkcs12.load_key_and_certificates(p12_data, password, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key, certificate

def extract_public_key(cert):
    """Retorna a chave publica do certificado. 
    Entrada: caminho certificado, Saída: public_key"""
    with open("Auth_cert/"+cert, 'rb') as file:
        file_data = file.read()
        cert = x509.load_pem_x509_certificate(file_data, backend=default_backend())
        public_key = cert.public_key()
        public_key_out = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        public_key_out = serialization.load_pem_public_key(public_key_out, backend=default_backend())
    return public_key_out