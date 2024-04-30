import os
import subprocess

# Função para criar usuário
def creat_unixUser(nome, senha):
    try:
        os.system(f"sudo useradd -m {nome}")
        os.system(f"sudo passwd {senha}")
        print(f"Usuário {nome} criado com sucesso!")
    except Exception as e:
        print(f"Erro ao criar usuário: {e}")



# Criar usuário de leitura com permissões limitadas
#criar_usuario("usuario_leitura", "senha456")

# Executar o processo de escrita com o usuário de escrita
#subprocess.run(['sudo', '-u', 'usuario_escrita', 'python3', 'processo_escrita.py'])

# Executar o processo de leitura com o usuário de leitura
#subprocess.run(['sudo', '-u', 'usuario_leitura', 'python3', 'processo_leitura.py'])

import os
import subprocess

# Função para criar grupo
def criar_grupo(nome):
    try:
        os.system(f"sudo groupadd {nome}")
        print(f"Grupo {nome} criado com sucesso!")
    except Exception as e:
        print(f"Erro ao criar grupo: {e}")

# Função para adicionar usuário a um grupo
def adicionar_usuario_a_grupo(usuario, grupo):
    try:
        os.system(f"sudo usermod -aG {grupo} {usuario}")
        print(f"Usuário {usuario} adicionado ao grupo {grupo}")
    except Exception as e:
        print(f"Erro ao adicionar usuário ao grupo: {e}")

# Criar grupo para os usuários
#criar_grupo("meugrupo")
"""
# Adicionar os usuários ao grupo
adicionar_usuario_a_grupo("usuario_escrita", "meugrupo")
adicionar_usuario_a_grupo("usuario_leitura", "meugrupo")

# Definir as permissões da diretoria para o grupo
try:
    os.system("sudo chown :meugrupo /AppMailBD/")
    os.system("sudo chmod g+r /caminho/para/diretoria")
    print("Permissões da diretoria definidas para o grupo com sucesso!")
except Exception as e:
    print(f"Erro ao definir as permissões da diretoria: {e}")

# Executar o processo de escrita com o usuário de escrita
subprocess.run(['sudo', '-u', 'usuario_escrita', 'python3', 'processo_escrita.py'])

# Executar o processo de leitura com o usuário de leitura
subprocess.run(['sudo', '-u', 'usuario_leitura', 'python3', 'processo_leitura.py'])
"""