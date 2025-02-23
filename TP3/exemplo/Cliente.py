from cryptography.hazmat.primitives.serialization import pkcs12
from message import *
import socket
import ssl
import os

def creat_socket(host, port):
    context = ssl.create_default_context()
    context.check_hostname= False
    context.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((host, port))
    return context.wrap_socket(sock, server_hostname=host)
    
class Cliente:
    def __init__(self, uid, pw):
        self.id = uid
        self.password = pw
        self.public_key = None
        self.private_key = None
        self.cert = None
        self.ca = None
        #self.server_socket = creat_socket("127.0.0.1", 12345)
        #self.autoridade_cert_socket = creat_socket("127.0.0.2", 12345)
        self.pks = {}
        self.unreadMSG = 0
        self.liveMsg = 0
        self.popup = "############"
        self.start()
        self.server_socket.close()
        self.autoridade_cert_socket.close()

    def updateMenu(self):
        if self.unreadMSG == 0 and self.liveMsg == 0:
            self.popup = "############"
        elif self.unreadMSG > 0 and self.liveMsg == 0:
            self.popup = " {} New Message! ".format(self.unreadMSG)
        elif self.unreadMSG > 0 and self.liveMsg > 0:
            self.popup = " {} New Message! AND {} Live Chat! ".format(self.unreadMSG, self.liveMsg)
        self.help = """#################{}#################
1- Check MAilBox!
2- Check Live Chat!
3- Send Message!
4- Start Live Chat!
9- Close app!
#################{}#################\n""".format(self.popup, "#"*len(self.popup))
        
    def start(self):
        #self.register()
        #self.server_handle()
        self.menu()

    def register(self):
        # peço a chave publica do server
        # envio pedido de registro no server
        public_key_server = self.pks['server']
        messagem = message(self.id, self.ca, "server", "0", "register", self.pk,"")
        messagem.serialize_public_key()
        cypher = messagem.serialize(public_key_server, self.sk)
        self.socket_send_msg(cypher)

    def server_handle(self):
        while self.status_socket:
            data = self.socket_recieve_msg(self.status_socket)
            if data == -1:
                    break
            mensagem_rec = message()
            if mensagem_rec.deserialize(data, self.private_key) == -1:
                print("MSG SERVICE: verification error!")
                break

    def menu(self):
        os.system('clear')
        self.updateMenu()
        option = int(input(self.help))
        while option != 9:
            if option == 3:
                self.send_message()
            elif option == 1:
                self.displayMailBox()
            elif option == 3:
                self.displayLiveChat()
            elif option == 4:
                self.startLiveChat()
            option = int(input(self.help))
     
    def send_message(self):
        print("\n#####################################################################")
        rid = input("Destinatário (Reciever): ")
        subject = input("Assunto (Subject): ")
        content = input("Mensagem (Content): ")
        print("#####################################################################\n")
        # saber se conheço o rid
        # se sim 
        # se não pedir ao server
        if rid not in self.pks.keys():
            if self.ask_4_pk(rid) != 0:
                print("MSG Serviço: Destinatŕio inválido!\n(MSG SERVICE: unknown user!)")
                return -1
        """Verifica se a mensagem possui menos de 1000 bytes.
        Assina, cifra, serializa e envia as mensagens ao server"""
        # Verificar tamanho do conteúdo menor que 1000 bytes
        message_bytes = content.encode('utf-8')
        if len(message_bytes) > 512:
            return print('A mensagem excedeu os 1000 bytes')
        # pk do servidor e do reciever
        public_key_server = self.pks['server']
        public_key_reciever = self.pks[rid]
        # Cifrar conteúdo. 1 para o servidor receber a mensagem.
        msg = message(self.id, self.ca, rid, '1', subject, content,"")
        # encriptar o conteudo
        msg.encrypt_content(public_key_reciever,self.sk)
        # Serializar a mensagem
        serialized_msg = msg.serialize(public_key_server, self.sk)
        self.socket_send_msg(serialized_msg)
        print('Mensagem enviada!(Message sent!)')  

    def displayMailBox(self):
        # percorrer a diretoria com o meu nome
        # desincriptar as ultimas 20 mensgens em caso de erro retornar erro no display
        pass

    def displayLiveChat(self):
        # perguntar quem esta a pedir live chat e aceitar ou rejeitar
        pass

    def startLiveChat(self):
        # começar o conversar com prints do lado direito e esquerdo
        left_text = "Texto alinhado à esquerda"
        right_text = "Texto alinhado à direita"

        # Usando formatação de string
        print("{:<30}{}".format(left_text, right_text))
        pass

    def ask_4_pk(self, rid):
        public_key_server = self.pks['server']
        msg = message(self.id, self.ca, 'server', '4', "ask_4_pk", rid, "")
        # Serializar a mensagem
        serialized_msg = msg.serialize(public_key_server, self.sk)
        self.socket_send_msg(serialized_msg)
        #print('Pedido de PK enviado!')
        # receber chave
        recieved_message = self.socket_recieve_msg()
        #dá serealize da chave
        rmsg = message()
        valid = rmsg.deserialize(recieved_message, self.sk)
        if valid == -1:
            print("MSG Serviço: Erro na verificação da assinatura!\n(MSG SERVICE: verification error!)")
            return -1
        if "unknown" not in rmsg.content:
            self.pks[rid] = serialization.load_pem_public_key(rmsg.content.encode('utf-8'))
            #print("Chave do {} recebida!".format(rid))
            return 0
        return -1
    
    def ask_queue(self, type):
        public_key_server = self.pks['server']
        messagem = message(self.id, self.ca, "server", type, "", "", "")
        cypher = messagem.serialize(public_key_server, self.sk)
        self.socket_send_msg(cypher)
        #print('Pedido de lista enviado!')
        recieved_message = self.socket_recieve_msg()
        msg = message()
        valid = msg.deserialize(recieved_message, self.sk)
        if valid == -1:
            print("MSG Serviço: Erro na verificação da assinatura!\n(MSG SERVICE: verification error!)")
            return -1
        print(msg.content)
        return 0

    def get_message(self, num):
        public_key_server = self.pks['server']
        msg = message(self.id, self.ca, "server", '3', "ask_msg", num, "")
        serialize = msg.serialize(public_key_server, self.sk)
        # Envia msg
        self.socket_send_msg(serialize)
        # Receber mensagem
        serialized_message = self.socket_recieve_msg()
        # Decerializar a mensagem 
        rmsg = message()
        valid = rmsg.deserialize(serialized_message, self.sk)
        if valid == -1:
            print("MSG Serviço: Erro na verificação da assinatura!\n(MSG SERVICE: verification error!)")
            return -1
        if rmsg.senderID not in self.pks.keys():
            self.ask_4_pk(rmsg.senderID)
        
        valida = rmsg.decrypt_content(self.sk,self.pks[rmsg.senderID])
        if valida == -1:
            print("MSG Serviço: Erro na verificação da assinatura!\n(MSG SERVICE: verification error!)")
            return -1
        if "MSG SERVICE: unknown message!" in rmsg.content:
            print("MSG Serviço: Não existe nenhuma mensagem com esse ID no servidor!\n(MSG SERVICE: unknown message ID!)")
        else:
            print("\n#####################################################################")
            print("Remetente (Sender): {}\nAssunto (Subject): {}\nMensagem (Content): {}".format(rmsg.senderID, rmsg.subject, rmsg.content))
            print("#####################################################################\n")
        return 0
    
    def socket_send_msg(self, msg):
        size = len(msg)
        tamanho_codificado = size.to_bytes(4, byteorder='big')
        mensagem_com_tamanho = tamanho_codificado + msg
        self.server_socket.sendall(mensagem_com_tamanho)

    def socket_recieve_msg(self, socket):
        size = socket.recv(4)
        try:
            tamanho_mensagem = int.from_bytes(size, byteorder='big')
            return socket.recv(tamanho_mensagem)
        except ValueError:
            self.socket_recieve_msg(socket)
        
def login(password=None):
    # Solicitar nome de usuário e senha ao usuário
    nome = input("Nome de usuário: ")
    password = input("Password: ")
    return Cliente(nome, password)



cliente = login()
