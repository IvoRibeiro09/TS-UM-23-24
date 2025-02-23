from socketFuncs.socketFuncs import creat_tcp_socket
import os

# ao arrancar criar um user server
class MasterUser:
    def __init__(self):
        self.server_socket = creat_tcp_socket('127.0.0.1', 12345)
        self.start()
        self.server_socket.close()

    def start(self):
        self.criarGrupo('code')
        diretorio_atual = os.getcwd()
        self.definirPermissoesGrupo('code',diretorio_atual, 777)
        self.server_socket.listen(1)            
        print("Aguardando conexões...")
        try:
            while True:
                # Aceitar conexão
                client_socket, client_address = self.server_socket.accept()
                # Receber mensagem do cliente
                while client_socket:
                    message = client_socket.recv(1024).decode()
                    if len(message) == 0: break
                    #print(f"Mensagem recebida: {message}")
                    # Criar um novo usuário usando o comando sudo
                    if "Criar novo user" in message:
                        data = message.split(": ")
                        udata = data[1].split(" - ")
                        r = self.criarUser(udata[0], udata[1])
                        client_socket.sendall(r.encode('utf-8'))
                    elif "Criar grupo:" in message:
                        data = message.split(": ")
                        r = self.criarGrupo(data[1])
                        client_socket.sendall(r.encode('utf-8'))
                    elif "Adicionar ao grupo:" in message:
                        data = message.split(": ")
                        udata = data[1].split(" - ")
                        r = self.adicionarUserGrupo(udata[0], udata[1])
                        client_socket.sendall(r.encode('utf-8'))
                    elif "Set permissoes grupo:" in message:
                        data = message.split(": ")
                        udata = data[1].split(",")
                        r = self.definirPermissoesGrupo(udata[0], udata[2], udata[1])
                        client_socket.sendall(r.encode('utf-8'))
                    elif "Set permissoes user:" in message:
                        data = message.split(": ")
                        udata = data[1].split(",")
                        r = self.definirPermissoesUser(udata[0], udata[2], udata[1])
                        client_socket.sendall(r.encode('utf-8'))
                    elif "Remover grupo:" in message:
                        data = message.split(": ")
                        r = self.removerGrupo(data[1])
                        client_socket.sendall(r.encode('utf-8'))
                    elif "Remover utilizador:" in message:
                        data = message.split(": ")
                        r = self.removerUtilizador(data[1])
                        client_socket.sendall(r.encode('utf-8'))

        except KeyboardInterrupt:
            self.server_socket.close()
            print("Master encerrado.")

    def criarUser(self, nome, pw):
        try:
            os.system(f"sudo useradd -m {nome}")
            os.system(f"echo '{nome}:{pw}' | sudo chpasswd")
            print(f"Usuário {nome} criado com sucesso!")
            self.adicionarUserGrupo(nome, 'code')
            return "SUCESS"
        except Exception as e:
            print(f"Erro ao criar usuário: {e}")
    
    def criarGrupo(self, nome):
        try:
            if os.system(f"sudo groupadd {nome}") < 0:
                return "Grupo já existe!"
            print(f"Grupo {nome} criado com sucesso!")
            return "SUCESS"
        except Exception as e:
            print(f"Erro ao criar grupo: {e}")

    # Função para adicionar usuário a um grupo
    def adicionarUserGrupo(self, usuario, grupo):
        try:
            if os.system(f"sudo usermod -aG {grupo} {usuario}") < 0:
                return f"Utilizador {usuario} ja pertence ao grupo {grupo}"
            print(f"Usuário {usuario} adicionado ao grupo {grupo}")
            return "SUCESS"
        except Exception as e:
            print(f"Erro ao adicionar usuário ao grupo: {e}")
    
    def definirPermissoesGrupo(self, grupo, diretoria, permissoes):
        try:
            if os.system(f"sudo chown :{grupo} {diretoria}") < 0:
                raise ValueError(" erro de vincar grupo a diretoria")
            if os.system(f"sudo chmod {permissoes} {diretoria}") < 0:
                raise ValueError("erro ao definir permissoes")
            print(f"Permissões {permissoes} da diretoria: {diretoria} definidas para o grupo {grupo} com sucesso!")
            return "SUCESS"
        except Exception as e:
            print(f"Erro ao definir as permissões da diretoria: {e}")

    def definirPermissoesUser(self, user, diretoria, permissoes):
        try:
            os.system(f"sudo chown {user}:{user} {diretoria}")
            os.system(f"sudo chmod {permissoes} {diretoria}")
            print(f"Permissões {permissoes} da diretoria: {diretoria} definidas para o user {user} com sucesso!")
            return "SUCESS"
        except Exception as e:
            print(f"Erro ao definir as permissões da diretoria: {e}")

    def removerGrupo(self, nome):
        try:
            os.system(f"sudo groupdel {nome}")
            os.system(f"sudo rm -r DataBase/{nome}")
            print(f"Grupo {nome} removida com sucesso!")
            return "SUCESS"
        except Exception as e:
            print(f"Erro ao remover grupo: {e}")

    def removerUtilizador(self, nome):
        try:
            os.system(f"sudo userdel {nome}")
            os.system(f"sudo rm -r DataBase/{nome}")
            print(f"User {nome} removido com sucesso!")
            return "SUCESS"
        except Exception as e:
            print(f"Erro ao remover utilizador: {e}")

MasterUser()