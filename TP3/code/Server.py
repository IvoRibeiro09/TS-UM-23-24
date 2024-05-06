import datetime
import os
import threading
from socketFuncs.socketFuncs import creat_tls_socket, join_tcp_socket
import cryptography.x509.oid as oid
from message import *
from Auth_cert.Auth_cert import load_data

class server:
    def __init__(self, uname, pw):
        self.username = uname
        self.password = pw
        self.privateKey, self.publicKey, self.ca = load_data(self.username)
        self.masters_con = join_tcp_socket('127.0.0.1', 12345)
        self.client_socket, self.cs_context = creat_tls_socket('127.0.0.2', 12345, self.ca, self.privateKey)
        self.start()
        self.masters_con.close()

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
                    r = "User já registado"
                    if os.path.exists(f"BD/{rmsg.senderID}"):
                        r = self.registeUser(rmsg.senderID, rmsg.content)  
                    msg = message('server', self.ca, rmsg.senderID, "0", 'regist-response', r, "")
                    data = msg.serialize(self.uData[rmsg.senderID].pk, self.privateKey)
                    msg.send(c_con, data)

                elif action == '1': # pedido de entrar num grupo
                    
                    print("LOG- Cliente {} enviou uma mensagem no dia {}!".format(uid,str(datetime.datetime.now())))
                
                elif action == '2': # criar grupo
                    pass

                elif action == '3' : # envio de mensagem 
                    
                    # guradar a mensagem numa pasta
                    # atualizar o ficehiro de logs do utilizador para o qual enviamos
                    pass
                elif action == '4': # pedido de livechat
                    if rmsg.content in self.uData.keys() and self.uData[rmsg.content].con != None:
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
                    pass
        finally:
            c_con.close()
    
    def login(self, nome, pw, result):
        if result == "SUCESS":
            if self.uData[nome].pw != pw: 
                result = "Invalid password!"
        msg = message('server', self.ca, nome, "0", "login", result, "")
        data = msg.serialize(self.uData[nome].publicKey, self.privateKey)
        msg.send(self.uData[nome].con, data)
  
    def registeUser(self, nome, msg_content):
        # separar a password da publik key

        # criar um User de linux

        # criar um user e adicionar à bd
        pass
        """
        if dicionario['content'] != 'unknown user':
            # Enviar mensagem ao master
            mensagem = f"Criar novo user: {nome} - {pword}"
            self.masters_con.sendall(mensagem.encode())
            data = self.masters_con.recv(1024)
            if data == "SUCESS":
                print("LOG- Cliente {} registado no dia {}!".format(nome, str(datetime.datetime.now())))
                return data
            else:
                raise "ERROR: criar utilizador!"
        else:
            return 'ERROR: Unknown User!'
            """
        
    def registeGruop(self, nome):
        message = f"Criar grupo: {nome}"
        self.masters_con.sendall(message.encode())
    
    def setGroupPermitions(self, nome, permissoes, direc):
        message = f"set permissoes: {nome},{permissoes},{direc}"
        self.masters_con.sendall(message.encode())



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