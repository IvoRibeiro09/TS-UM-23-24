import csv
import datetime
import os
import threading
from socketFuncs.socketFuncs import creat_tls_socket, join_tcp_socket
import cryptography.x509.oid as oid
from message import *
from Auth_cert.Auth_cert import load_data

serverPath = "BD/server/"

def get_user_pk(nome):
    if not os.path.exists(f"{serverPath}pk-{nome}.pem"):
       raise ValueError("User não esta na base de dados")
    else:
        with open(f"{serverPath}pk-{nome}.pem", "rb") as file:
            file_data = file.read()
        cert = x509.load_pem_x509_certificate(file_data, backend=default_backend())
        public_key = cert.public_key()
        public_key_out = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        public_key_out = serialization.load_pem_public_key(public_key_out, backend=default_backend())
        return public_key_out
    
def write_pk_file(nome, content):
    with open(f"{serverPath}pk-{nome}.pem", "wb") as file:
        # Serializa a chave pública no formato PEM
        pem = content.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Escreve a chave pública serializada no arquivo
        file.write(pem)

def write_pw_file(nome, content):
    with open(f"{serverPath}pw-{nome}.pw", "wb") as file:
        file.write(content)

class server:
    def __init__(self, uname, pw):
        self.username = uname
        self.password = pw
        self.privateKey, self.publicKey, self.ca = load_data(self.username)
        self.masters_con = join_tcp_socket('127.0.0.1', 12345)
        self.client_socket, self.cs_context = creat_tls_socket('127.0.0.2', 12345, self.ca, self.privateKey)
        self.uCons = {}
        self.start()
        self.masters_con.close()

    def start(self):
        if not os.path.exists("BD"): os.makedirs("BD")
        if not os.path.exists("BD/serverBD"): os.makedirs("BD/serverBD")
        self.registeGruop('serverBD')
        self.setUserToGroup(self.username,'serverBD')
        self.setGroupPermitions('serverBD','0o600', 'BD/serverBD')
        try:
            self.client_socket.listen()
            print("Servidor aberto!!")
            while True:
                # Aguardar por novas conexões
                newsocket, client_address = self.client_socket.accept()
                client_connection = self.cs_context.wrap_socket(newsocket, server_side=True)
                # Criar uma thread para lidar com a conexão de cada cliente
                client_thread = threading.Thread(target=self.handleClient, args=(client_connection, client_address))
                client_thread.start()
        except KeyboardInterrupt:
            self.client_socket.close()
            print("Servidor encerrado.")

    def handleClient(self, c_con, c_add):
        print(f"Conexão estabelecida com {c_add}")
        try:
            while True:
                rmsg = message()
                data = rmsg.recieve(c_con)
                if rmsg.deserialize(data, self.privateKey) < 0:
                    raise ValueError("MSG SERVICE: verification error!")
                
                for attribute in rmsg.senderCA.subject:
                    if attribute.oid == oid.NameOID.PSEUDONYM:
                        uid = attribute.value
                        break 
                if uid != rmsg.senderID: raise ValueError("Erro utilizador invalido")
                
                action = rmsg.action
                if action == '0': # registrar
                    r = "User já registado"
                    if not os.path.exists(f"BD/{rmsg.senderID}"):
                        r = self.registeUser(rmsg.senderID, rmsg)  
                        if r == "SUCESS": self.uCons[rmsg.senderID] = c_con
                    msg = message('server', self.ca, rmsg.senderID, "0", 'regist-response', r, "")
                    data = msg.serialize(get_user_pk(rmsg.senderID), self.privateKey)
                    msg.send(c_con, data)

                elif action == '1': # pedido de entrar num grupo
                    
                    print("LOG- Cliente {} enviou uma mensagem no dia {}!".format(uid,str(datetime.datetime.now())))
                
                elif action == '2': # criar grupo
                    pass

                elif action == '3' : # envio de mensagem 
                    # guradar a mensagem numa pasta
                    valido = self.guardar_mensagem(rmsg)
                    # atualizar o ficheiro de logs do utilizador para o qual enviamos
                    if valido>0:
                        print(f"LOG- Mensagem recebida do utlizador {rmsg.senderID} para o utilizador {rmsg.reciverID}.")
                        valido = self.user_logs(rmsg.reciverID,rmsg,valido)
                    else:
                        print(f"LOG- Erro ao guardar mensagem do utlizador {rmsg.senderID} na pasta do utilizador {rmsg.reciverID}.")
                elif action == '4': # pedido de livechat
                    if rmsg.content in self.uCons.keys() and self.uData[rmsg.content].con != None:
                        msg = message('server', self.ca, rmsg.content, '5', 'livechat', rmsg.senderID, "")
                        msg.serialize(self.uData[rmsg.content].publicKey, self.privateKey)
                        msg.send(self.uData[rmsg.content].c_con)
                    else: 
                        #error response
                        pass
                elif action == '5': # resposta a pedido de livechat
                    if rmsg.content == 'Accept':
                        # abrir um ficehiro no live msg com permissoes de leitura dos dois clientes
                        # e enviar a indicação aos dois clientes com o nome do ficehiro
                        # a escrever tem ser cli1 - o que ele escreveu
                        # para eles perceberem
                        # eles vao abrir e ler
                        pass
                elif action == '6': #escrever no ficehiro comum as mensagens recebidas
                    with open(f'{rmsg.subject}.txt', "a") as arquivo:  
                        # Escrever no arquivo o conteudo com o nome dele antes cli1 - 
                        arquivo.write("Nova linha!\n")
                    pass

                elif action == '7': # login user
                    r = self.login(rmsg.senderID, rmsg.content)
                    msg = message('server', self.ca, rmsg.senderID, "7", 'login-response', r, "")
                    data = msg.serialize(self.uData[rmsg.senderID].pk, self.privateKey)
                    msg.send(c_con, data)
        finally:
            c_con.close()
    
    def login(self, nome, pw, result):
        if result == "SUCESS":
            if self.uData[nome].pw != pw: 
                result = "Invalid password!"
        msg = message('server', self.ca, nome, "0", "login", result, "")
        data = msg.serialize(self.uData[nome].publicKey, self.privateKey)
        msg.send(self.uData[nome].con, data)
  
    def registeUser(self, nome, rmsg):
        # separar a password da publik key
        password, pk = unpair(rmsg.content.encode('utf-8'))
        rmsg.content = pk.decode('utf-8')
        rmsg.deserialize_public_key()
        # criar um User de linux
        # Enviar mensagem ao master
        mensagem = f"Criar novo user: {nome} - {password.decode('utf-8')}"
        self.masters_con.sendall(mensagem.encode())
        data = self.masters_con.recv(1024).decode('utf-8')
        if data == "SUCESS":
            print("LOG- Cliente {} registado no dia {}!".format(nome, str(datetime.datetime.now())))
        else:
            return data
        # criar um fichiero com a password e outro com a pk
        write_pk_file(nome, rmsg.content)
        write_pw_file(nome, password)
        return data
            
    def registeGruop(self, nome):
        message = f"Criar grupo: {nome}"
        self.masters_con.sendall(message.encode())
        data = self.masters_con.recv(1024).decode('utf-8')
        if data == "SUCESS":
            print("LOG- Grupo {} registado no dia {}!".format(nome, str(datetime.datetime.now())))
        return data
    
    def setGroupPermitions(self, nome, permissoes, direc):
        message = f"set permissoes: {nome},{permissoes},{direc}"
        self.masters_con.sendall(message.encode())

    def guardar_mensagem(self,mensagem_rec):
        mensagem_env = message(mensagem_rec.senderID, self.certificate, mensagem_rec.reciverID, '3', mensagem_rec.subject, mensagem_rec.content, mensagem_rec.contentsign)
            
        chave_receiber = get_user_pk(mensagem_rec.reciverID)
        cypher = mensagem_env.serialize(chave_receiber, self.privateKey)
        
        if os.path.exists(f"BD/{mensagem_rec.reciverID}"):
            number = len(os.listdir(f"BD/{mensagem_rec.reciverID}"))
            while os.path.exists(f"BD/{mensagem_rec.reciverID}/{number}.bin"):
                number+=1

            with open(f"BD/{mensagem_rec.reciverID}/{number}.bin", "wb+") as file:
                file.write(cypher)
            return number
        else:
            return-1

    def user_logs(self,utilizador,msg,number):
        if os.path.exists(f"BD/{utilizador}"):
            with open("BD/{utilizador}/log.csv", mode='a+', newline='') as arquivo_csv:
                escritor_csv = csv.writer(arquivo_csv)
                linha = [number,msg.senderID,str(datetime.datetime.now()),msg.subject,"FALSE"]
                escritor_csv.writerow(linha)
            return 1
        else:
            return-1

username = 'server'
password = 'root'
server(username, password)
#  sudo -u server python3 serverAPI.py

# Colocar permissões de leitura aos menbros do grupo MailViewer

"""# Dar permissões de leitura e escrita para o usuario1
sudo chown usuario1:grupo_principal diretorio
sudo chmod 750 diretorio

# Dar permissões de leitura apenas para o usuario2
sudo chown usuario2:subgrupo diretorio
sudo chmod 550 diretorio"""