import threading, datetime
from socket import socket, AF_INET, SOCK_STREAM
from ssl import SSLContext, PROTOCOL_TLS_SERVER
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization, hashes
import cryptography.x509.oid as oid
from message import * 
import os
import json
import csv

##meter um cifragem qualquer para a chave privada para nao guarda la simples(o certificado tambem)
def load_data(password=None):
    with open("SERVER.p12", "rb") as file:
        p12_data = file.read()
    private_key, certificate, _ = pkcs12.load_key_and_certificates(p12_data, password)
    
    public_key = private_key.public_key()
    
    with open("auth_server/SERVER.crt", "wb+") as file:
        certificate_1 = certificate.public_bytes(encoding=serialization.Encoding.PEM)
        file.write(certificate_1)
    with open("auth_server/SERVER.pem", "wb+") as file:
        private_key_1 = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        file.write(private_key_1)
    
    return private_key, public_key, certificate

def load_usersdata(uid,password=None):
    with open(f"auth_server/users/{uid}.p12", "rb") as file:
        p12_data = file.read()
    private_key, certificate, _ = pkcs12.load_key_and_certificates(p12_data, password)
    
    public_key = private_key.public_key()
    
    return private_key, public_key, certificate

class Server:
    def __init__(self, host, port):
        if not os.path.exists("auth_server"):
            os.makedirs(f"auth_server")
        if not os.path.exists("auth_server/users"):
            os.makedirs(f"auth_server/users")

        #arquivo_existe = os.path.isfile("auth_server/log.csv")
        #with open("auth_server/log.csv", mode='a+', newline='') as arquivo_csv:
        #    escritor_csv = csv.writer(arquivo_csv)
        #    
        #    # Se o arquivo não existir, adicionar um cabeçalho
        #    if not arquivo_existe:
        #        escritor_csv.writerow(['IP/PORT','TIPO_DE_PEDIDO','TIME', 'CONTENT'])

        private_key, public_key, certificate = load_data()
        self.private_key = private_key
        self.certificate=certificate

        self.pk = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

        self.context = SSLContext(PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain("auth_server/SERVER.crt", "auth_server/SERVER.pem")

        self.server_socket = socket(AF_INET, SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen()

        self.host = host
        self.port = port

        self.credenciais = {"CLI1":{'pass':"123",'uid':'CLI1'},"CLI2":{'pass':"123",'uid':'CLI2'},"CLI3":{'pass':"123",'uid':'CLI3'}}

        print(f"Servidor aberto ({self.host} : {self.port})")

    def verifica_credenciais(self,username,password):
        if self.credenciais[username]['pass'] == password:
            return self.credenciais[username]['uid']
        else:
            return -1
    
    def get_chave(self,uid):
        if not os.path.exists(f"auth_server/users/{uid}"):
            return -1

        _, public_key, _ = load_usersdata(uid)

        return public_key
        
    def new_client(self,UID,mensagem_rec):
        user = self.get_user(UID)
        if user != None:
            #print("Utilizador ja existe")
            return -1        
        chave_recevida = mensagem_rec.senderCA.public_key()
        chave_recevida = chave_recevida.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        cl = User(UID)
        
        with open(f"server/pks/{UID}.pk", "wb+") as f:
            f.write(chave_recevida)
        
        self.users.append(cl)

    def new_group(self,UID,mensagem_rec):
        user = self.get_user(UID)
        if user != None:
            #print("Utilizador ja existe")
            return -1        
        chave_recevida = mensagem_rec.senderCA.public_key()
        chave_recevida = chave_recevida.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        cl = User(UID)
        
        with open(f"server/pks/{UID}.pk", "wb+") as f:
            f.write(chave_recevida)
        
        self.users.append(cl)
    
    def ask_key(self,uid,mensagem_rec):
        ## buscar a chave pretendida
        uid_pretendido = mensagem_rec.content
        chave = self.get_chave(uid_pretendido)

        #mensagem de resposta
        if chave == -1:
            mensagem_env = message("server", self.certificate, uid,"4", "Nao existe chave", "unknown user","")
        else:
            mensagem_env = message("server", self.certificate, uid,"4", "", chave.decode("utf-8"),"")
        
        cypher = str(mensagem_env.generate()).enconde('utf-8')
        
        return cypher
    
    def ask_dados(self,mensagem_rec):
        ## buscar os dados pessoais
        uid = self.verifica_credenciais(mensagem_rec.username,mensagem_rec.password)
        if not os.path.exists(f"auth_server/users/{uid}"):
            user = -1
        else:
            user = 1
        
        if user != -1 and uid != -1:
            private_key, public_key, certificate = load_usersdata(uid)
            response = {'sk':private_key,'pk':public_key,'crt':certificate}

        #mensagem de resposta
        if user == -1 and uid == -1:
            mensagem_env = message("server", self.certificate, uid,"3", "credenciais erradas", "unknown user","")
        else:
            mensagem_env = message("server", self.certificate, uid,"3", "", str(response),"")
        
        cypher = mensagem_env.serialize(self.pk, self.private_key)
        
        return cypher
    
    def socket_send_msg(self, msg,connection):
            size = len(msg)
            tamanho_codificado = size.to_bytes(4, byteorder='big')
            mensagem_com_tamanho = tamanho_codificado + msg
            connection.sendall(mensagem_com_tamanho)

    def socket_recieve_msg(self,connection):
        size = connection.recv(4)
        try:
            tamanho_mensagem = int.from_bytes(size, byteorder='big')
            if tamanho_mensagem == 0:
                return -1
            cypher = connection.recv(tamanho_mensagem+1)
            return cypher
        except ValueError:
            print("Error - Socket buffer com conteúdo inválido!")
            self.socket_recieve_msg(connection)
            
    def handle_client(self, connection, address):
        print(f"Conexão estabelecida com {address}")
        try:
            while True:
                # Receber dados do cliente
                data = self.socket_recieve_msg(connection)
                if data == -1:
                    break

                mensagem_rec = message()
                valid = mensagem_rec.deserialize(data, self.private_key)
                               
                if valid == -1:
                    print("MSG SERVICE: verification error!")
                    break
                
                action = mensagem_rec.action
                if action == '0': ################# registrar
                    self.new_client(mensagem_rec)
                else:
                    for attribute in mensagem_rec.senderCA.subject:
                        if attribute.oid == oid.NameOID.PSEUDONYM:
                            uid = attribute.value
                            break
                    
                    assert uid == mensagem_rec.senderID, "Erro utilizador invalido"

                    if action == '1': ############### registrar grupo
                        self.new_group(mensagem_rec,data)
                    elif action == '2': ############### pedir chave publica
                        self.ask_key(mensagem_rec,data)
                    elif action == '3': ############### pedir dados pessoais
                        self.ask_dados(mensagem_rec,data)
                    
        finally:
            # Fechar a conexão com o cliente
            connection.close()
            print(f"Conexão encerrada com {address}")

    def start(self):
        try:
            while True:
                # Aguardar por novas conexões
                newsocket, client_address = self.server_socket.accept()
                client_connection = self.context.wrap_socket(newsocket, server_side=True)
                # Criar uma thread para lidar com a conexão do cliente
                client_thread = threading.Thread(target=self.handle_client, args=(client_connection, client_address))
                client_thread.start()
        except KeyboardInterrupt:
            print("Servidor encerrado.")
        finally:
            # Fechar o socket do servidor
            self.server_socket.close()

# Configurações do servidor
HOST = '127.0.0.3'  # Endereço IP local
PORT = 12345        # Porta a ser utilizada

# Criar e iniciar o servidor
server = Server(HOST, PORT)
server.start()
