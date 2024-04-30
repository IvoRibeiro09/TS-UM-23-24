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