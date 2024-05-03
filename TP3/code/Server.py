import os
import socket
import threading
from socketFuncs.socketFuncs import creat_socket, join_socket
import cryptography.x509.oid as oid
from message import *

class User:
    def __init__(self, id, pw, pk):
        self.id = id
        self.pw = pw
        self.publicKey = pk
        self.unreadmsg = []
        self.livechats = []


class server:
    def __init__(self):
        # ligar à autoridade certificadora
        self.auth_cert_socket = join_socket('127.0.0.3', 12345)
        self.privateKey, self.publicKey, self.ca = self.load_data_AC()
        self.masters_con = socket(AF_INET, SOCK_STREAM)
        self.masters_con.connect(('127.0.0.1', 12345))
        self.client_socket, self.cs_context = creat_socket('127.0.0.2', 12345, self.ca, self.privateKey)
        self.uData = {}
        self.start()
        self.masters_con.close()

    def load_data_AC(self):
        # msg para a autoriDADE certificadora a pedir os meus dados
        pass

    def start(self):
        if not os.path.exists("BD"): os.makedirs("BD")
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
            print("Servidor encerrado.")
        finally:
            # Fechar o socket do servidor
            self.client_socket.close()

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
                    if rmsg.senderID in self.uData.keys():
                        # se exister logar
                        self.login(rmsg.senderID)
                    else:
                        # se n exister registar 
                        self.registeUser(rmsg.senderID, rmsg.content)
                    
                elif action == '1': # pedido de entrar num grupo
                    
                    print("LOG- Cliente {} enviou uma mensagem no dia {}!".format(uid,str(datetime.datetime.now())))
                
                elif action == '2': # criar grupo
                    pass

                elif action == '3' : # envio de mensagem 
                    # guradar a mensagem numa pasta
                    # atualizar o ficehiro de logs do utilizador para o qual enviamos
                    pass
                elif action == '4': # pedido de livechat
                    pass
        finally:
            c_con.close()
    
    def login(self, nome, result=None):
        if result != None:
            msg = message('server', self.ca, nome, "0", "login", result, "")
            msg.serialize(self.uData[nome].publicKey, self.privateKey)
  
    def registeUser(self, nome, pword):
        # pedir a chave publica do nome à autoridade certificadora
        
        message = "Criar novo usuário"
        # Enviar mensagem ao master
        self.masters_con.sendall(message.encode())
        """if rmsg.send(self.masters_con) == "SUCESS":
            print("LOG- Cliente {} registado no dia {}!".format(nome, str(datetime.datetime.now())))
        else:
            raise ValueError("ERROR: criar utilizador!")"""
        self.login(nome, "Invalid inicialization!")
        
    def registeGruop(self, nome):
        message = f"Criar grupo: {nome}"
        self.masters_con.sendall(message.encode())
    
    def setGroupPermitions(self, nome, permissoes, direc):
        message = f"set permissoes: {nome},{permissoes},{direc}"
        self.masters_con.sendall(message.encode())


server()
#  sudo -u server python3 serverAPI.py

# Colocar permissões de leitura aos menbros do grupo MailViewer

"""# Dar permissões de leitura e escrita para o usuario1
sudo chown usuario1:grupo_principal diretorio
sudo chmod 750 diretorio

# Dar permissões de leitura apenas para o usuario2
sudo chown usuario2:subgrupo diretorio
sudo chmod 550 diretorio"""