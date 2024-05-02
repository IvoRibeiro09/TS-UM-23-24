import os, pwd
import socket
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12
from socket import socket, AF_INET, SOCK_STREAM
from ssl import SSLContext, PROTOCOL_TLS_SERVER


# remover depois
def load_data(password=None):
    with open("SERVER.p12", "rb") as file:
        p12_data = file.read()
    private_key, certificate, _ = pkcs12.load_key_and_certificates(p12_data, password, backend=default_backend())
    public_key = private_key.public_key()
    with open("SERVER.crt", "wb+") as file:
        certificate_1 = certificate.public_bytes(encoding=serialization.Encoding.PEM)
        file.write(certificate_1)
    with open("SERVER.pem", "wb+") as file:
        private_key_1 = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        file.write(private_key_1)
    return private_key, public_key, certificate

class server:
    def __init__(self):
        # ligar à autoridade certificadora
        self.privateKey, self.publicKey, self.ca = load_data()
        self.masters_con = socket(AF_INET, SOCK_STREAM)
        self.masters_con.connect(('127.0.0.1', 12345))
        self.client_socket = socket(AF_INET, SOCK_STREAM)
        self.client_socket.bind(('127.0.0.2', 12345))
        self.context = SSLContext(PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain("SERVER.crt", "SERVER.pem")
        self.start()
        self.masters_con.close()

    def start(self):
        if not os.path.exists("BD"): os.makedirs("BD")
        try:
            self.client_socket.listen()
            while True:
                # Aguardar por novas conexões
                newsocket, client_address = self.client_socket.accept()
                client_connection = self.context.wrap_socket(newsocket, server_side=True)
                # Criar uma thread para lidar com a conexão de cada cliente
                client_thread = threading.Thread(target=self.handleClient, args=(client_connection, client_address))
                client_thread.start()
        except KeyboardInterrupt:
            print("Servidor encerrado.")
        finally:
            # Fechar o socket do servidor
            self.client_socket.close()

    def handleClient(c_con, c_add):
        pass
  
    def registeUser(self):
        # Mensagem para enviar ao servidor
        message = "Criar novo usuário"
        # Enviar mensagem ao servidor
        self.masters_con.sendall(message.encode())

    def registeGruop(self, nome):
        message = f"Criar grupo: {nome}"
        self.masters_con.sendall(message.encode())
    
    def setGroupPermitions(self, nome, permissoes, direc):
        message = f"set permissoes: {nome},{permissoes},{direc}"
        self.masters_con.sendall(message.encode())


user_info = pwd.getpwnam("server")
# Definir o UID do processo para o UID do usuário "server"
os.setuid(user_info.pw_uid)

server()

# Colocar permissões de leitura aos menbros do grupo MailViewer

"""# Dar permissões de leitura e escrita para o usuario1
sudo chown usuario1:grupo_principal diretorio
sudo chmod 750 diretorio

# Dar permissões de leitura apenas para o usuario2
sudo chown usuario2:subgrupo diretorio
sudo chmod 550 diretorio"""