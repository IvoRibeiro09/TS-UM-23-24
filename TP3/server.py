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
    
    with open("server/SERVER.crt", "wb+") as file:
        certificate_1 = certificate.public_bytes(encoding=serialization.Encoding.PEM)
        file.write(certificate_1)
    with open("server/SERVER.pem", "wb+") as file:
        private_key_1 = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        file.write(private_key_1)
    
    return private_key, public_key, certificate
    
## falta a cifragem dos ficheiros se for necessario
class User:
    def __init__(self,uid,env=0,rec=0):
        self.uid = uid
        self.number_env = env
        self.number_rec = rec
        if not os.path.exists(f"server/{uid}"):
            os.makedirs(f"server/{uid}")
        if not os.path.exists(f"server/{uid}/rec"):
            os.makedirs(f"server/{uid}/rec")
        if not os.path.exists(f"server/{uid}/env"):
            os.makedirs(f"server/{uid}/env")

    def add_send_message(self,uid,cypher):
        assert self.uid == uid, "Nao tem permissoes para escrever neste user"
        
        with open(f"server/{uid}/env/{self.number_env}.msg", "wb+") as f:
            f.write(cypher)
        self.number_env+=1

    def add_message(self,uid,cypher):
        assert self.uid == uid, "Nao tem permissoes para escrever neste user"
    
        with open(f"server/{uid}/rec/{self.number_rec}.msg", "wb+") as f:
            f.write(cypher)
        self.number_rec+=1
    
    def get_message(self,uid,number):
        assert self.uid == uid, "Nao tem permissoes para escrever neste user"
        
        with open(f"server/{uid}/rec/{number}.msg", "rb") as f:
                m = f.read()

        return m

    def get_uid(self):
        return self.uid

class Server:
    def __init__(self, host, port):
        if not os.path.exists("server"):
            os.makedirs(f"server")
        if not os.path.exists("server/pks"):
            os.makedirs(f"server/pks")
        
        arquivo_existe = os.path.isfile("server/log.csv")
        with open("server/log.csv", mode='a+', newline='') as arquivo_csv:
            escritor_csv = csv.writer(arquivo_csv)
            
            # Se o arquivo não existir, adicionar um cabeçalho
            if not arquivo_existe:
                escritor_csv.writerow(['NUM','SENDER','TIME', 'SUBJECT','RECEIBER',"LIDA"])

        private_key, public_key, certificate = load_data()
        self.private_key = private_key
        self.certificate=certificate

        pk = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        with open(f"server/pks/server.pk", "wb+") as f:
            f.write(pk)

        self.context = SSLContext(PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain("server/SERVER.crt", "server/SERVER.pem")

        self.server_socket = socket(AF_INET, SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen()

        self.host = host
        self.port = port

        self.users = []
        uids = [nome for nome in os.listdir('server')]
        uids.remove('pks')
        uids.remove('SERVER.crt')
        uids.remove('SERVER.pem')
        uids.remove('log.csv')
        for uid in uids:
            caminho_do_diretorio = f'server/{uid}/env'
            if os.path.exists(caminho_do_diretorio):
                numero_de_env = len(os.listdir(caminho_do_diretorio))
            else:
                numero_de_env = 0
            caminho_do_diretorio = f'server/{uid}/rec'
            if os.path.exists(caminho_do_diretorio):
                numero_de_rec = len(os.listdir(caminho_do_diretorio))
            else:
                numero_de_rec = 0
            user = User(uid,env=numero_de_env,rec=numero_de_rec)
            self.users.append(user)

        print(f"Servidor aberto ({self.host} : {self.port})")

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

    def get_user(self,UID):
        for user in self.users:
            if user.get_uid() == UID:
                return user
            
    def receive(self,message,cypher):
        Uid = message.reciverID
        sender_id = message.senderID

        user = self.get_user(Uid)
        user.add_message(Uid,cypher)
        
        sender = self.get_user(sender_id)
        sender.add_send_message(sender_id,cypher)

        with open("server/log.csv", mode='a+', newline='') as arquivo_csv:
            escritor_csv = csv.writer(arquivo_csv)
            linha = [str(user.number_rec-1),sender_id,str(datetime.datetime.now()),message.subject,Uid,"FALSE"]
            escritor_csv.writerow(linha)

    def queue (self,UID,type):
        dados = []
        if type == '2':
            lida = 'FALSE'
        else:
            lida = 'TRUE'
        with open("server/log.csv", mode='r', newline='') as arquivo_csv:
            leitor_csv = csv.reader(arquivo_csv)
            # Iterando sobre as linhas do arquivo CSV
            for linha in leitor_csv:
                if linha[4]==UID and linha[5] == lida:
                    dados.append(linha)
        resposta = ""
        for linha in dados:
            resposta += "ID: " + linha[0] +", SENDER: "+ linha[1] + ", TIME: " + linha[2] + ", SUBJECT: " + linha[3] + "\n"
        if resposta == "":
            resposta = "\nNão tem nenhuma mensagem por ler no servidor!\n(There are no unread messages on the server!)\n"

        mensagem_env = message("server", self.certificate,UID,type, "", resposta,"")
        chave_recetor = self.get_chave(UID)
        cypher = mensagem_env.serialize(chave_recetor,self.private_key)
        return cypher
    
    def get_message(self, UID, mensagem_rec):
        number = mensagem_rec.content
        # recoperar a cifra guardada
        user = self.get_user(UID)

        existe = False
        with open("server/log.csv", mode='r', newline='') as arquivo_csv:
            leitor_csv = csv.reader(arquivo_csv)
            linhas = list(leitor_csv)

        for linha in linhas:
            if linha[0] == str(number) and linha[4] == UID:
                linha[5]= "TRUE"
                existe = True
                break

        # Escrever o conteúdo modificado de volta para o arquivo
        with open("server/log.csv", mode='w', newline='') as arquivo_csv:
            escritor_csv = csv.writer(arquivo_csv)
            escritor_csv.writerows(linhas)

        chave_recetor = self.get_chave(UID)
        aux_msg = message()

        if existe:
            ciphertext_guardada = user.get_message(UID, number)    
            aux_msg.deserialize(ciphertext_guardada, self.private_key)
            mensagem_env = message(aux_msg.senderID, self.certificate, UID, '3', aux_msg.subject, aux_msg.content, aux_msg.contentsign)
        else:
            mensagem_env = message('server', self.certificate, UID, '3', "Mensagem nao existe", 'MSG SERVICE: unknown message!', "")
            mensagem_env.encrypt_content(chave_recetor,self.private_key)

        cipher = mensagem_env.serialize(chave_recetor, self.private_key)
        return cipher

    def asking_key(self,uid,mensagem_rec):
        uid_pretendido = mensagem_rec.content
        ## buscar a chave pretendida
        chave = self.get_chave(uid_pretendido)
        if chave == -1:
            mensagem_env = message("server", self.certificate, uid,"4", "Nao existe chave", "unknown user","")
        else:
            chave = chave.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            mensagem_env = message("server", self.certificate, uid,"4", "", chave.decode("utf-8"),"")
        chave_recetor = self.get_chave(uid)
        #mensagem_env.encrypt_content(chave_recetor)
        cypher = mensagem_env.serialize(chave_recetor, self.private_key)
        
        return cypher

    def get_chave (self,UID):
        if not os.path.exists(f"server/pks/{UID}.pk"):
            return -1
        with open(f"server/pks/{UID}.pk", "rb") as key_file:
            pk = serialization.load_pem_public_key(key_file.read())
        return pk
    
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
                
                for attribute in mensagem_rec.senderCA.subject:
                    if attribute.oid == oid.NameOID.PSEUDONYM:
                        uid = attribute.value
                        break
                
                assert uid == mensagem_rec.senderID, "Erro utilizador invalido"
                
                action = mensagem_rec.action
                if action == '0': ################# registrar
                    self.new_client(uid,mensagem_rec)
                    print("LOG- Cliente {} registado no dia {}!".format(uid,str(datetime.datetime.now())))
                elif action == '1': ############### recebe uma mensagem
                    self.receive(mensagem_rec,data)
                    print("LOG- Cliente {} enviou uma mensagem no dia {}!".format(uid,str(datetime.datetime.now())))
                elif action == '2' or action == '5': ############### pedido para ver as fila das mensagens
                    cypher = self.queue(uid,action)
                    self.socket_send_msg(cypher,connection)
                    if action == '2':print("LOG- Cliente {} pediu lista de mensagens por ler no dia {}!".format(uid,str(datetime.datetime.now())))
                    else: print("LOG- Cliente {} pediu lista de mensagens já lidas no dia {}!".format(uid,str(datetime.datetime.now())))
                elif action == '3': ############### pedido para ver uma mensagem
                    cypher = self.get_message(uid,mensagem_rec)
                    self.socket_send_msg(cypher,connection)
                    print("LOG- Cliente {} pediu o envio da mensagem com ID:{} no dia {}!".format(uid,mensagem_rec.content,str(datetime.datetime.now())))
                elif action == '4': ############### pedido de uma chave publica de outro utilizador
                    cypher = self.asking_key(uid,mensagem_rec)
                    self.socket_send_msg(cypher,connection)
                    print("LOG- Cliente {} pediu a chave publica do utilizador com ID:{} no dia {}!".format(uid,mensagem_rec.content,str(datetime.datetime.now())))
                    
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
HOST = '127.0.0.1'  # Endereço IP local
PORT = 12345        # Porta a ser utilizada

# Criar e iniciar o servidor
server = Server(HOST, PORT)
server.start()
