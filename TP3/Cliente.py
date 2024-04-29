from cryptography.hazmat.primitives.serialization import pkcs12
from message import *
from cryptography import x509
import socket
import ssl
import threading

def extract_public_key(cert):
    """Retorna a chave publica do certificado. 
    Entrada: caminho certificado, Saída: public_key"""
    with open(cert, 'rb') as file:
        file_data = file.read()
        cert = x509.load_pem_x509_certificate(file_data)
        public_key = cert.public_key()
        public_key_out = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        public_key_out = serialization.load_pem_public_key(public_key_out)
    return public_key_out

def creat_socket(host, port):
    context = ssl.create_default_context()
    context.check_hostname= False
    context.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((host, port))
    return context.wrap_socket(sock, server_hostname=host)
    
class Cliente:
    def __init__(self, uid, pk, sk, cert, ca):
        self.id = uid
        self.pk = pk
        self.sk = sk
        self.cert = cert
        self.ca = ca
        self.server_socket = creat_socket("127.0.0.1", 12345)
        self.status_socket = creat_socket("127.0.0.1", 12345)
        self.pks = {"server": extract_public_key('SERVER.crt')}
        self.help = """\nOpções:
1- Enviar Mensagem!
2- Ver mensagens não lidas!
3- Pedir mensagem!
4- Rever mensagens já lidas!
9- Fechar aplicação!\n"""
        self.start()
        self.server_socket.close()
        self.status_socket.close()

    def start(self):
        self.register()
        # uma thread para o menu e outra para o handler
        # abrir a interface menu 
        # ouvir o server para conexões de status
        menu = threading.Thread(target=self.menu)
        handler = threading.Thread(target=self.handler)
        menu.start()
        handler.start()

    def register(self):
        public_key_server = self.pks['server']
        messagem = message(self.id, self.ca, "server", "0", "register", self.pk,"")
        messagem.serialize_public_key()
        cypher = messagem.serialize(public_key_server, self.sk)
        self.socket_send_msg(cypher)

    def menu(self):
        option = int(input(self.help))
        while option != 9:
            if option == 1:
                print("\n#####################################################################")
                rid = input("Destinatário (Reciever): ")
                subj = input("Assunto (Subject): ")
                msg = input("Mensagem (Content): ")
                print("#####################################################################\n")
                # saber se conheço o rid
                # se sim 
                # se não pedir ao server
                if rid not in self.pks.keys():
                    if self.ask_4_pk(rid) == 0:
                        self.send_message(rid, subj, msg)
                    else:
                        print("MSG Serviço: Destinatŕio inválido!\n(MSG SERVICE: unknown user!)")
                else:
                    self.send_message(rid, subj, msg)
            elif option == 2:
                self.ask_queue("2")
            elif option == 4:
                self.ask_queue("5")
            elif option == 3:
                num = input("Qual o ID da mensagem que queres receber: \n(What is the ID of the message you want to receive)\n")
                self.get_message(num)
            option = int(input(self.help))

    def handler(self):
        while self.status_socket:
            data = self.socket_recieve_msg(self.status_socket)
            if data == -1:
                    break
            mensagem_rec = message()
            if mensagem_rec.deserialize(data, self.private_key) == -1:
                print("MSG SERVICE: verification error!")
                break
                
        pass
        
    def send_message(self, rid, subject, content):
        """Verifica se a mensagem possui menos de 1000 bytes.
        Assina, cifra, serializa e envia as mensagens ao server"""
        # Verificar tamanho do conteúdo menor que 1000 bytes
        message_bytes = content.encode('utf-8')
        if len(message_bytes) > 1000:
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
    senha = input("Certificado (inserir o nome do ficheiro com terminação .crt): ")
    with open(senha[:-4]+".p12", "rb") as file:
        p12_data = file.read()
    private_key, user_ca, _ = pkcs12.load_key_and_certificates(p12_data, password)
    public_key = private_key.public_key()
    return Cliente(nome, public_key, private_key, senha, user_ca)


cliente = login()