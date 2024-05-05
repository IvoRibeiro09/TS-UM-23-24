from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from message import *
from socketFuncs.socketFuncs import join_tls_socket
import os

def load_data(file, password=None):
    with open(f"{file}.p12", "rb") as file:
        p12_data = file.read()
    private_key, certificate, _ = pkcs12.load_key_and_certificates(p12_data, password, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key, certificate

def extract_public_key(cert):
    """Retorna a chave publica do certificado. 
    Entrada: caminho certificado, Saída: public_key"""
    with open(cert, 'rb') as file:
        file_data = file.read()
        cert = x509.load_pem_x509_certificate(file_data)
        public_key = cert.public_key()
        public_key_out = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        public_key_out = serialization.load_pem_public_key(public_key_out)
    return public_key_out

class cliente:
    def __init__(self):
        self.id, self.pw = self.login()
        self.privateKey, self.publicKey, self.ca = load_data(self.id)
        self.server_socket = join_tls_socket("127.0.0.2", 12345)
        self.pks = {"server": extract_public_key('SERVER.crt')}
        self.start()
        self.server_socket.close()
        self.switch_user()

    def login(self):
        nome = input("Nome de usuário: ")
        password = input("Password: ")
        return nome, password
    
    def start(self):
        self.register()
        self.sendpk()
    
    def register(self):
        # encryptar e assinar o conteudo e mandar a assinatura no message
        msg = message(self.id, self.ca, 'server', "0", "login", self.pw, "")
        msg.serialize(self.pks['server'], self.privateKey)
        msg.send(self.server_socket)
        rmsg = message()
        rmsg.recieve(self.server_socket)
        if rmsg.content == "SUCESS":
            print("Login efetuado!")
        else:
            raise ValueError(rmsg.content)
    
    def sendpk(self):
        msg = message(self.id, self.ca, 'server', "7", "sendpk", self.publicKey, "")
        msg.serialize(self.pks['server'], self.privateKey)
        msg.send(self.server_socket)

    def switch_user(self):
        # Definir o UID do usuário do sistema Linux para outro usuário válido
        os.system(f"sudo -u {self.id} python3 Cliente.py")
    
cliente()
