from message import *
from socketFuncs.socketFuncs import join_tls_socket
from Auth_cert.Auth_cert import load_data, extract_public_key
import os, sys, csv

path = 'DataBase/'

class cliente:
    def __init__(self, name, pw):
        self.username = name
        self.password = pw
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
        self.updateMenu()
        option = int(input(self.help))
        os.system('clear')
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
        # percorrer a diretoria com o meu nome
        # ler o ficehiro csv 
        new = 0
        with open(f"{path}{self.username}/log.csv", newline='') as arquivo_csv:
            leitor_csv = csv.reader(arquivo_csv)
            for linha in leitor_csv:
                print(linha)
                if "nLida" in linha:
                    new+=1
        
        if new == 0:
            print("Não tem mensagens novas!")
        # dar display das mensagens la descritas com não lidas
        # desincriptar as ultimas 20 mensgens em caso de erro retornar erro no display

    def displayLiveChat(self):
        texto = "\n"
        self.recieveMSGs()
        while '!exit' not in texto:
            os.system('clear')
            print("Live Chat Mode!")
            if 'ask-' in texto:
                msg = message(self.username, self.ca, 'server', '4', 'live-chat', texto,"")
            elif "acpt-" in texto:
                msg = message(self.username, self.ca, 'server', '4', 'live-chat', texto,"")
            else:
                msg = message(self.username, self.ca, 'server', '4', 'live-chat', "start","")
            serialized_msg = msg.serialize(self.pks['server'], self.privateKey)
            msg.send(self.server_socket, serialized_msg) 
            # receber resposta
            rmsg = message()
            cypher = rmsg.recieve(self.server_socket)
            rmsg.deserialize(cypher, self.privateKey)
            if "user:" in rmsg.content:
                data = rmsg.content.split(":")
                for i in range(1, len(data)):
                    print(f"-> Utilizador {data[i]} disponivel!")
                print("\n\task-{user} to ask for a LiveChat!\n\tacpt-{user} to accept a LiveChat!\n\tPress ENTER to refresh!\n\t!exit to exit")
            elif "accept" in rmsg.content:
                data = rmsg.content.split(":")
                self.startLiveChat(data[1])
            texto = input(": ")
        # perguntar quem esta a pedir live chat e aceitar ou rejeitar

    def startLiveChat(self, lvchat):
        print(lvchat)
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