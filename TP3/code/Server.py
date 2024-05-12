import csv
import datetime
import os
import threading
import time
from socketFuncs.socketFuncs import creat_tls_socket, join_tcp_socket
import cryptography.x509.oid as oid
from message import *
from Auth_cert.Auth_cert import load_data

serverPath = "DataBase/server/"
path = "DataBase/"

def get_user_pk(nome):
    if not os.path.exists(f"{serverPath}pk-{nome}.pem"):
        if os.path.exists(f"{path}{nome}"):##significa que é um grupo
            return 0
        else:
            raise ValueError("User ou grupo não esta na base de dados")
    else:
        with open(f"{serverPath}pk-{nome}.pem", "rb") as file:
            file_data = file.read()
            return serialization.load_pem_public_key(file_data, backend=default_backend())
    
def write_pk_file(nome, content):
    with open(f"{serverPath}pk-{nome}.pem", "wb") as file:
        # Serializa a chave pública no formato PEM
        pem = content.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Escreve a chave pública serializada no arquivo
        file.write(pem)

def get_user_pw(nome):
    with open(f"{serverPath}pw-{nome}.pw", "rb") as file:
        return file.read()

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
        self.livechats = {}
        self.nlivechats = 0
        self.files = {}
        self.start()
        self.masters_con.close()

    def start(self):
        self.registeGruop(self.username)
        self.setUserToGroup(self.username, self.username)
        if not os.path.exists("DataBase"): os.makedirs("DataBase")
        if not os.path.exists(f"DataBase/{self.username}"): os.makedirs(f"DataBase/{self.username}")
        self.setUserPermitions(self.username, '740', f"DataBase/{self.username}")
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
                if not os.path.exists(f"{path}{rmsg.senderID}"):
                    r = self.registeUser(rmsg.senderID, rmsg)
                    if r == "SUCESS": self.uCons[rmsg.senderID] = c_con
                msg = message('server', self.ca, rmsg.senderID, "0", 'regist-response', r, "")
                data = msg.serialize(get_user_pk(rmsg.senderID), self.privateKey)
                msg.send(c_con, data)
            elif action == '7': # login user
                r = self.login(rmsg.senderID, rmsg.content)
                msg = message('server', self.ca, rmsg.senderID, "7", 'login-response', r, "")
                data = msg.serialize(get_user_pk(rmsg.senderID), self.privateKey)
                msg.send(c_con, data)
            else:
                raise ValueError("Erro na autenticaçao")
                
            while True:
                rmsg = message()
                data = rmsg.recieve(c_con)
                if len(data) != 0:
                    if rmsg.deserialize(data, self.privateKey) < 0:
                        raise ValueError("MSG SERVICE: verification error!")
                    
                    for attribute in rmsg.senderCA.subject:
                        if attribute.oid == oid.NameOID.PSEUDONYM:
                            uid = attribute.value
                            break 
                    if uid != rmsg.senderID: raise ValueError("Erro utilizador invalido")
                    
                    action = rmsg.action

                    if action == '1': # pedido de entrar num grupo
                        valid = rmsg.decrypt_content(self.privateKey,get_user_pk(rmsg.senderID))
                        if valid > 0:
                            data = self.setUserToGroup(rmsg.senderID,rmsg.content)
                            if data != "SUCESS":
                                print(f"LOG- Falha ao registrar {rmsg.senderID} no Grupo {rmsg.content}")
                        else:
                            print(f"LOG- Falha ao decifrar content")   

                    elif action == '2': # criar grupo
                        valid = rmsg.decrypt_content(self.privateKey,get_user_pk(rmsg.senderID))
                        if valid > 0:
                            data = self.registeGruop(rmsg.content)
                            nome = rmsg.content
                            if data == "SUCESS":
                                if not os.path.exists(f"{path}{nome}"): os.makedirs(f"{path}{nome}")
                                open(f"{path}{nome}/log.csv", "w")
                                self.setGroupPermitions(nome, '750', f"{path}{nome}")
                                data = self.setUserToGroup(rmsg.senderID,rmsg.content)
                                if data != "SUCESS":
                                    print(f"LOG- Falha ao registrar {rmsg.senderID} no Grupo {rmsg.content}")
                            else:
                                print(f"LOG- Falha ao criar Grupo {rmsg.content}")
                        else:
                            print(f"LOG- Falha ao decifrar content")

                    elif action == '3' : # guradar a mensagem numa pasta
                        valido = self.guardar_mensagem(rmsg)
                        if valido > 0:
                            print(f"LOG- Mensagem recebida do utlizador {rmsg.senderID} para o utilizador {rmsg.reciverID}.")
                            valido = self.user_logs(rmsg.reciverID,rmsg,valido)
                        else:
                            print(f"LOG- Erro ao guardar mensagem do utlizador {rmsg.senderID} na pasta do utilizador {rmsg.reciverID}.")
                
                    elif action == '4': # pedido de livechat
                        self.uCons[rmsg.senderID] = c_con
                        self.livechatControl(rmsg.senderID, rmsg.content, c_con)

                    elif action == '6': #escrever no ficehiro comum as mensagens recebidas
                        with open(self.files[rmsg.senderID], "a") as file:
                            texto = rmsg.content
                            file.write(f"{rmsg.senderID}- {texto}\n")

                    elif action == '8': # por as mensagens como lidas
                        valid = rmsg.decrypt_content(self.privateKey,get_user_pk(rmsg.senderID))
                        if valid == -1:
                            print(f"LOG- Erro ao decifrar content da mensagem do utlizador {rmsg.senderID}.")
                        else:
                            num = eval(rmsg.content)
                            if rmsg.subject == '':
                                user =rmsg.senderID
                            else:
                                user =rmsg.subject
                            with open(f"{path}{user}/log.csv", mode='r', newline='') as arquivo_csv:
                                leitor_csv = csv.reader(arquivo_csv)
                                linhas = list(leitor_csv)
                            for linha in linhas:
                                if linha[0] in num:
                                    if rmsg.subject == '':
                                        linha[4]= "TRUE"
                                    else:
                                        lis = eval(linha[4])
                                        lis.append(rmsg.senderID)
                                        linha[4]=str(lis)
                            # Escrever o conteúdo modificado de volta para o arquivo
                            with open(f"{path}{user}/log.csv", mode='w', newline='') as arquivo_csv:
                                escritor_csv = csv.writer(arquivo_csv)
                                escritor_csv.writerows(linhas)
                            print(f"LOG- Atualizaçao da leitura de mensagens do utlizador {rmsg.senderID}.")

                    elif action == '5': # sair do grupo
                        self.removerGrupo(rmsg.content)

                    elif action == '9': # remover utilizador
                        print("remover utilizador")
                        valid = rmsg.decrypt_content(self.privateKey,get_user_pk(rmsg.senderID))
                        if valid > 0:
                            print("remover utilizador")
                            r = self.login(rmsg.senderID, rmsg.content)
                            if r == "SUCESS":
                                self.removerUser(rmsg.senderID)

        except Exception as e:
            print(e)
        finally:
            print(f"Conexão fechada com {c_add}")
            c_con.close()
    
    def login(self, nome, pw):
        if get_user_pw(nome).decode('utf-8') != pw: 
            return "Invalid password!"
        else:
            return "SUCESS"
    
    def registeUser(self, nome, rmsg):
        # separar a password da publik key
        password, pk = unpair(rmsg.content.encode('utf-8'))
        rmsg.content = pk.decode('utf-8')
        pk = rmsg.deserialize_public_key()
        r = self.registeUserMaster(nome, password.decode('utf-8'))  
        self.registeGruop(nome)
        self.setUserToGroup(nome, nome)
        os.makedirs(f"{path}{nome}")
        open(f"{path}{nome}/log.csv", "w")
        self.setGroupPermitions(nome, '750', f"{path}{nome}")
        write_pk_file(nome, pk)
        write_pw_file(nome, password)
        return r
    
    def registeUserMaster(self, nome, password):
        # criar um User de linux
        # Enviar mensagem ao master
        mensagem = f"Criar novo user: {nome} - {password}"
        self.masters_con.sendall(mensagem.encode())
        data = self.masters_con.recv(1024).decode('utf-8')
        if data == "SUCESS":
            print("LOG- Cliente {} registado no dia {}!".format(nome, str(datetime.datetime.now())))
        # criar um fichiero com a password e outro com a pk
        #self.setUserToGroup(nome, 'server')
        return data
            
    def registeGruop(self, nome):
        message = f"Criar grupo: {nome}"
        self.masters_con.sendall(message.encode())
        data = self.masters_con.recv(1024).decode('utf-8')
        if data == "SUCESS":
            print("LOG- Grupo {} registado no dia {}!".format(nome, str(datetime.datetime.now())))
        return data
    
    def setUserToGroup(self, nome, group):
        mensagem = f"Adicionar ao grupo: {nome} - {group}"
        self.masters_con.sendall(mensagem.encode())
        data = self.masters_con.recv(1024).decode('utf-8')
        if data == "SUCESS":
            print("LOG- Cliente {} adicionado ao grupo {} registado no dia {}!".format(nome, group, str(datetime.datetime.now())))
        return data
    
    def setGroupPermitions(self, nome, permissoes, direc):
        message = f"Set permissoes grupo: {nome},{permissoes},{direc}"
        self.masters_con.sendall(message.encode())
        data = self.masters_con.recv(1024).decode('utf-8')
        if data == "SUCESS":
            print("LOG- Permissoes {} adicionadas à diretoria {} para o grupo {} registado no dia {}!".format(permissoes, direc, nome, str(datetime.datetime.now())))
        return data
    
    def setUserPermitions(self, nome, direc, permissoes):
        message = f"Set permissoes user: {nome},{direc},{permissoes}"
        self.masters_con.sendall(message.encode())
        data = self.masters_con.recv(1024).decode('utf-8')
        if data == "SUCESS":
            print("LOG- Permissoes {} adicionadas à diretoria {} para o grupo {} registado no dia {}!".format(permissoes, direc, nome, str(datetime.datetime.now())))
        return data

    def guardar_mensagem(self,mensagem_rec):
        chave_receiber = get_user_pk(mensagem_rec.reciverID)
        if chave_receiber == 0:
            cypher = f"Subject:{mensagem_rec.subject}\nSenderID:{mensagem_rec.senderID}\nContent:{mensagem_rec.content}".encode('utf-8')
        else:
            mensagem_env = message(mensagem_rec.senderID, self.ca, mensagem_rec.reciverID, '3', mensagem_rec.subject, mensagem_rec.content, mensagem_rec.contentsign)
            cypher = mensagem_env.serialize(chave_receiber, self.privateKey)
        if os.path.exists(f"{path}{mensagem_rec.reciverID}"):
            number = len(os.listdir(f"{path}{mensagem_rec.reciverID}"))
            while os.path.exists(f"{path}{mensagem_rec.reciverID}/{number}.bin"):
                number+=1
            with open(f"{path}{mensagem_rec.reciverID}/{number}.bin", "wb+") as file:
                file.write(cypher)
            return number
        else:
            return-1

    def user_logs(self,utilizador,msg,number):
        user = True
        if not os.path.exists(f"{serverPath}pk-{utilizador}.pem"):
            user = False
        
        if os.path.exists(f"{path}{utilizador}"):
            with open(f"{path}{utilizador}/log.csv", mode='a+', newline='') as arquivo_csv:
                escritor_csv = csv.writer(arquivo_csv)
                if user:
                    linha = [number,msg.senderID,str(datetime.datetime.now()),msg.subject,"FALSE"]
                else:
                    linha = [number,msg.senderID,str(datetime.datetime.now()),msg.subject,'[]']
                escritor_csv.writerow(linha)
            return 1
        else:
            return-1
        
    def livechatControl(self, nome, content, c_con):
        if '!start' in content:
            self.livechats[nome] = 1
            texto = ""
            for i in self.livechats.keys(): 
                if self.livechats[i] == 1 and i != nome:
                    texto += i + "está disponivel para livechat!\n"
            msg = message('server', self.ca, nome, '4', 'livechat', texto, "")
            cypher = msg.serialize(get_user_pk(nome), self.privateKey)
            msg.send(c_con, cypher)
            print(f"LOG- User {nome} em modo liveChat!")
        elif '!acpt-' in content:
            data = content.split('-')
            if data[1] in self.livechats.keys():
                self.livechats[nome] = 2
                self.livechats[data[1]] = 2
                self.nlivechats += 1
                lv = self.nlivechats 
                msg = message('server', self.ca, nome, '4', 'livechat', f"accept:lvchat{lv}", "")
                cypher1 = msg.serialize(get_user_pk(nome), self.privateKey)
                msg.send(c_con, cypher1)
                msg = message('server', self.ca, data[1], '4', 'livechat', f"accept:lvchat{lv}", "")
                cypher2 = msg.serialize(get_user_pk(data[1]), self.privateKey)
                msg.send(self.uCons[data[1]], cypher2)
                self.livechatRun(nome, data[1], f"lvchat{lv}")
                print(f"LOG- User {nome} aceitou livechat com {data[1]}!")
        elif '!ask-' in content:
            data = content.split('-')
            print(data[1])
            msg = message('server', self.ca, data[1], '4', 'livechat', nome +" enviou um pedido de livechat!", "")
            cypher = msg.serialize(get_user_pk(data[1]), self.privateKey)
            msg.send(self.uCons[data[1]], cypher)
            print(f"LOG- User {nome} pediu livechat com {data[1]}!")
        elif "!exit" in content:
            print(f"LOG- User {nome} saiu do modo liveChat!")
            time.sleep(0.5)
            self.livechats[nome] = 0
            data = self.files[nome].split("/")
            self.removerGrupo(data[1])
            self.files[nome] = ""
        
    def livechatRun(self, u1, u2, dir):
        if not os.path.exists(f"{path}{dir}"): os.makedirs(f"{path}{dir}")
        with open(f"{path}{dir}/lv.txt", "w") as file: pass
        self.registeGruop(f"{dir}")
        self.setGroupPermitions(f"{dir}", 350, f"{path}{dir}")
        self.setUserToGroup(u1, f"{dir}")
        self.setUserToGroup(u2, f"{dir}")
        self.files[u1] = f"{path}{dir}/lv.txt"
        self.files[u2] = f"{path}{dir}/lv.txt"
    
    def removerGrupo(self, nome):
        if not os.path.exists(f"{path}{nome}"):
            print(f"LOG- Grupo {nome} já não existe!({str(datetime.datetime.now())})")
        else:
            message = f"Remover grupo: {nome}"
            self.masters_con.sendall(message.encode())
            data = self.masters_con.recv(1024).decode('utf-8')
            if data == "SUCESS":
                print(f"LOG- Grupo {nome} removido!({str(datetime.datetime.now())})")
            else:
                print(f"ERROR- Remoção do grupo {nome}!({str(datetime.datetime.now())})")
            
    def removerUser(self, nome):
        if not os.path.exists(f"{path}{nome}"):
            print(f"LOG- User {nome} já não existe!({str(datetime.datetime.now())})")
        else:
            message = f"Remover utilizador: {nome}"
            self.masters_con.sendall(message.encode())
            data = self.masters_con.recv(1024).decode('utf-8')
            if data == "SUCESS":
                os.system(f"rm -r {serverPath}pw-{nome}.pw")
                os.system(f"rm -r {serverPath}pk-{nome}.pem")
                print(f"LOG- Utilizador {nome} removido!({str(datetime.datetime.now())})")
            else:
                print(f"ERROR- Remoção do utilizador {nome}!({str(datetime.datetime.now())})")


username = 'server'
password = 'root'
server(username, password)
#  sudo -u server python3 serverAPI.py