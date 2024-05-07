from message import *
from socketFuncs.socketFuncs import join_tls_socket
from Auth_cert.Auth_cert import load_data, extract_public_key
import os, sys, csv

path = 'DataBase/'

class cliente:
    def __init__(self, name, pw):
        self.username = name
        self.password = pw
        #self.masters_con = join_tcp_socket('127.0.0.1', 12345)
        self.privateKey, self.publicKey, self.ca = load_data(self.username)
        self.server_socket = join_tls_socket("127.0.0.2", 12345)
        self.pks = {"server": extract_public_key('SERVER.crt'), 
                    "CLI1":extract_public_key('CLI1.crt'),
                    "CLI2":extract_public_key('CLI2.crt'),
                    "CLI3":extract_public_key('CLI3.crt')}
        self.unreadMSG = 0
        self.liveMsg = 0
        self.popup = "############"
        self.start()
        self.server_socket.close()

    def start(self):
        self.menu()
        
    def updateMenu(self):
        if self.unreadMSG == 0 and self.liveMsg == 0:
            self.popup = "############"
        elif self.unreadMSG > 0 and self.liveMsg == 0:
            self.popup = " {} New Message! ".format(self.unreadMSG)
        elif self.unreadMSG > 0 and self.liveMsg > 0:
            self.popup = " {} New Message! AND {} Live Chat! ".format(self.unreadMSG, self.liveMsg)
        self.help = """{}\n1- Check MAilBox!\n2- Check Live Chat!\n3- Send Message!
4- Start Live Chat!\n9- Close app!\n{}\n""".format((12*"#")+self.popup+(12*"#"), "#"*(24+len(self.popup)))

    def menu(self):
        os.system('clear')
        self.updateMenu()
        option = int(input(self.help))
        while option != 9:
            if option == 3:
                self.send_message()
            elif option == 1:
                self.displayMailBox()
            elif option == 2:
                self.displayLiveChat()
            elif option == 4:
                self.startLiveChat()
            self.updateMenu()
            option = int(input(self.help))
            os.system('clear')
     
    def send_message(self):
        os.system('clear')
        print("#####################################################################")
        rid = input("Destinatário (Reciever): ")
        subject = input("Assunto (Subject): ")
        content = input("Mensagem (Content): ")
        print("#####################################################################\n")
        # saber se conheço o rid
        # se sim 
        # se não pedir ao server
        if rid not in self.pks.keys():
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
        msg = message(self.username, self.ca, rid, '3', subject, content,"")
        # encriptar o conteudo
        msg.encrypt_content(public_key_reciever,self.privateKey)
        # Serializar a mensagem
        serialized_msg = msg.serialize(public_key_server, self.privateKey)
        msg.send(self.server_socket, serialized_msg)
        print('Mensagem enviada!(Message sent!)')  

    def displayMailBox(self):
        os.system('clear')
        # percorrer a diretoria com o meu nome
        # ler o ficehiro csv 
        nao_lidas = []
        with open(f"{path}{self.username}/log.csv", newline='') as arquivo_csv:
            leitor_csv = csv.reader(arquivo_csv)
            for linha in leitor_csv:
                if linha[4]=='FALSE':
                    nao_lidas.append((linha[0],linha[1]))

        if len(nao_lidas) == 0:
            print("Não tem mensagens novas!")
        else:
            num=[]
            for msg in nao_lidas:
                with open(f"{path}{self.username}/{msg[0]}.bin", "rb") as file:
                    file_data = file.read()
                rmsg = message()
                if rmsg.deserialize(file_data, self.privateKey) < 0:
                    raise ValueError("MSG SERVICE: verification error!")
                rmsg.decrypt_content(self.privateKey,self.pks[msg[1]])
                print(f"Message number:{msg[0]}\nSubject: {rmsg.subject}\nContent: {rmsg.content}\n")
            msg = message(self.username, self.ca, 'server', '', num, "")
            msg.serialize(get_user_pk[data[1]], self.privateKey)
            msg.send(self.server_socket)
        # dar display das mensagens la descritas com não lidas
        # desincriptar as ultimas 20 mensgens em caso de erro retornar erro no display

    def displayLiveChat(self):
        texto = "\n"
        msg = message(self.username, self.ca, 'server', '4', 'live-chat', "start","")
        serialized_msg = msg.serialize(self.pks['server'], self.privateKey)
        msg.send(self.server_socket, serialized_msg)
        while '!exit' not in texto:
            os.system('clear')
            print("Live Chat Mode!")
            rmsg = message()
            cypher = rmsg.recieve(self.server_socket)
            rmsg.deserialize(cypher, self.privateKey)
            if "Nenhum user disponivel" in rmsg.content:
                print(rmsg.content)
                print("Press ENTER to refresh!")
            elif "pedido" in rmsg.content:
                print(rmsg.content)
            elif "aceite" in rmsg.content:
                self.startLiveChat(rmsg.content)
            texto = input(": ")
        # perguntar quem esta a pedir live chat e aceitar ou rejeitar

    def startLiveChat(self, lvchat):
        try: 
            texto = input("\n: ")
            while texto != 'exit':
                with open(f"{path}{lvchat}/{lvchat}.txt", newline='') as arquivo_csv:
                    leitor_csv = csv.reader(arquivo_csv)
                    for linha in leitor_csv:
                        data = linha.split('- ')
                        if data[0] == self.username:
                            print("{:<30}{}".format("", data[1]))
                        else:
                            print("{:<30}{}".format(data[1], ""))
                msg = message(self.username, self.ca, lvchat, '6', 'live-chat', texto,"")
                serialized_msg = msg.serialize(self.pks['server'], self.privateKey)
                msg.send(self.server_socket, serialized_msg)
                texto = input("\n: ")
        finally:
            return 
        """
        # começar o conversar com prints do lado direito e esquerdo
        left_text = "Texto alinhado à esquerda"
        right_text = "Texto alinhado à direita"

        # Usando formatação de string
        print("{:<30}{}".format(left_text, right_text))
        pass
        """

    
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
        

if __name__ == "__main__":
    # Verificar se há argumentos passados na linha de comando
    if len(sys.argv) != 3:
        print("Uso: python3 Cliente.py arg1 arg2")
        sys.exit(1)
    cliente(sys.argv[1], sys.argv[2])