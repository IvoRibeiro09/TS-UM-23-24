from message import *
from socketFuncs.socketFuncs import join_tls_socket
import os
from Auth_cert.Auth_cert import load_data, extract_public_key


class cliente:
    def __init__(self):
        self.id, self.pw = self.login()
        self.privateKey, self.publicKey, self.ca = load_data(self.id)
        self.server_socket = join_tls_socket("127.0.0.2", 12345)
        self.pks = {"server": extract_public_key('SERVER.crt')}
        self.start()
        self.server_socket.close()
        self.switch_user()

    def login(self):
        nome = input("Nome de usuário: ")
        password = input("Password: ")
        return nome, password
    
    def start(self):
        option = int(input("1- Register!\n2- Login!\n"))
        while True:
            if option == 1:
                r = self.register() 
            elif option == 2:
                r = self.sendLogin()
            if r == 0: break
            option = int(input("1- Register!\n2- Login!\n"))
               
    
    def register(self):
        # encryptar e assinar o conteudo e mandar a assinatura no message
        msg = message(self.id, self.ca, 'server', "0", "regist", self.publicKey, "")
        msg.serialize_public_key()
        data = mkpair(self.pw.encode('utf-8'), msg.content.encode('utf-8'))
        msg.content = data.decode('utf-8')
        cypher = msg.serialize(self.pks['server'], self.privateKey)
        msg.send(self.server_socket, cypher)
        rmsg = message()
        cypher = rmsg.recieve(self.server_socket)
        rmsg.deserialize(cypher, self.privateKey)
        if rmsg.content == "SUCESS":
            print("User Registado com sucesso!")
            return 0
        else:
            print(f"{rmsg.content}")
            return -1
    
    def sendLogin(self):
        msg = message(self.id, self.ca, 'server', "7", "login", self.pw, "")
        cypher = msg.serialize(self.pks['server'], self.privateKey)
        msg.send(self.server_socket, cypher)
        rmsg = message()
        data = rmsg.recieve(self.server_socket)
        rmsg.deserialize(data, self.privateKey)
        if rmsg.content == "SUCESS":
            print("Login efetuado com sucesso!")
            return 0
        else:
            print(f"{rmsg.content}")
            return -1

    def switch_user(self):
        # Definir o UID do usuário do sistema Linux para outro usuário válido
        os.system(f"sudo -u {self.id} python3 Cliente.py {self.id} {self.pw}")
    
cliente()
