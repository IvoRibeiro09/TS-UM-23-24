from socketFuncs.socketFuncs import creat_tcp_socket
import os

# ao arrancar criar um user server
class MasterUser:
    def __init__(self):
        self.server_socket = creat_tcp_socket('127.0.0.1', 12345)
        self.start()
        self.server_socket.close()

    def start(self):
        self.server_socket.listen(1)            
        print("Aguardando conexões...")
        while True:
            # Aceitar conexão
            client_socket, client_address = self.server_socket.accept()
            # Receber mensagem do cliente
            message = client_socket.recv(1024).decode()
            print(f"Mensagem recebida: {message}")
            # Criar um novo usuário usando o comando sudo
            if "Criar novo user" in message:
                data = message.split("Criar novo user: ")
                print(data[1])
                udata = data[1].split(" - ")
                self.criarUser(udata[0], udata[1])
            # Fechar conexões
            client_socket.close()

    def criarUser(self, nome, pw):
        print(nome, pw)
        """
        try:
            os.system(f"sudo useradd -m {nome}")
            os.system(f"sudo passwd {pw}")
            print(f"Usuário {nome} criado com sucesso!")
        except Exception as e:
            print(f"Erro ao criar usuário: {e}")
            """
    
    def criarGrupo(self, nome):
        try:
            os.system(f"sudo groupadd {nome}")
            print(f"Grupo {nome} criado com sucesso!")
        except Exception as e:
            print(f"Erro ao criar grupo: {e}")

    # Função para adicionar usuário a um grupo
    def adicionarUserGrupo(self, usuario, grupo):
        try:
            os.system(f"sudo usermod -aG {grupo} {usuario}")
            print(f"Usuário {usuario} adicionado ao grupo {grupo}")
        except Exception as e:
            print(f"Erro ao adicionar usuário ao grupo: {e}")
    
    def definirPermissoes(self, grupo, diretoria, permissoes):
        try:
            os.system(f"sudo chown {grupo} {diretoria}")
            os.system(f"sudo chmod {permissoes} {diretoria}")
            print(f"Permissões {permissoes} da diretoria: {diretoria} definidas para o grupo {grupo} com sucesso!")
        except Exception as e:
            print(f"Erro ao definir as permissões da diretoria: {e}")

MasterUser()


'''
import os

nome = input("Server: ")
if (os.system(f"sudo useradd -m {nome}") == 0):
    os.system(f"sudo passwd {nome}")

group = "code"
# grupo de acesso à diretoria do codigo
os.system(f"sudo groupadd {group}")
# adicionar a diretoria com código ao grupo
diretorio_codigo = os.getcwd()
# Alterar o grupo do diretório para o grupo 'code'
os.system(f"sudo chown :{group} {diretorio_codigo}")
# Dar permissão de execução para o grupo 'code'
os.system(f"sudo chmod g+x {diretorio_codigo}/*")
# adicionar o server ao grupo
os.system(f"sudo usermod -aG {group} {nome}")


# Correr o server como server
comando = (
    f"sudo -u {nome} bash -c '"
    f"cd {diretorio_codigo} && "
    "python3 serverAPI.py'"
)
os.system(comando)
'''

'''
import subprocess

nome = "exemplo_usuario"
senha = "nova_senha"

# Execute o comando passwd e defina a senha do usuário sem interação
process = subprocess.Popen(['sudo', 'passwd', nome], stdin=subprocess.PIPE)
process.communicate(input=senha.encode())
'''