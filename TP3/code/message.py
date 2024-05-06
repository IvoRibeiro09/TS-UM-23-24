import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
# todas as msg tens de ser enviadas com o certificado do autor
# gerar um par de chaves em ambos os clientes
# passar a chave publica ao servidor com o certificado do mesmo
# encriptar o content com um algotitmo entre a private key e chave publica do outro
# encriptar a message com um algoritmo que o server consiga decifrar


def escape_special_characters(string):
    # Função para escapar caracteres especiais
    escaped_string = string.replace('"', '\\"')  # Escapar aspas duplas
    escaped_string = string.replace('./', 'exec ')  # Escapar aspas duplas
    # Adicione mais substituições de caracteres especiais, se necessário
    return escaped_string

def encrypt(plaintext, receiverPK):
    # Gerar uma chave AES aleatória
    aes_key = os.urandom(32)  # 32 bytes = 256 bits
    iv = os.urandom(16)  # 16 bytes = 128 bits
    # Criptografar os dados com a chave AES
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    # Criptografar a chave AES com a chave pública RSA do destinatário
    encrypted_aes_key = receiverPK.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Obter o tag de autenticação
    authentication_tag = encryptor.tag
    ciphertextmsg = base64.b64encode(encrypted_aes_key 
                            + iv
                            + authentication_tag
                            + ciphertext
                            )
    return ciphertextmsg

def decrypt(encrypted_data, receiver_sk):
    # Decodificar os dados criptografados da base64
    encrypted_data_bytes = base64.b64decode(encrypted_data)
    # Extrair a chave AES criptografada e o texto cifrado
    encrypted_aes_key = encrypted_data_bytes[:256]  # Tamanho da chave RSA OAEP
    iv = encrypted_data_bytes[256:272]
    tag = encrypted_data_bytes[272:288]
    ciphertext = encrypted_data_bytes[288:]
    # Descriptografar a chave AES com a chave privada RSA do destinatário
    aes_key = receiver_sk.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Decifrar os dados usando a chave AES e o IV
    # Inicializar o objeto decryptor com o IV e o tag de autenticação
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag)
    ).decryptor()
    # Descriptografar os dados
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def Sign(content, key):
    signature = key.sign(
        content,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def Verify(signature, recieved_message, sender_pk):
        signature_bytes = base64.b64decode(signature)
        try:
            sender_pk.verify(
                signature_bytes,
                recieved_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return 1
        except Exception as e:
            return -1
        
def mkpair(x, y):
    """ produz uma byte-string contendo o tuplo '(x,y)' ('x' e 'y' são byte-strings) """
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, 'little')
    return len_x_bytes + x + y

def unpair(xy):
    """ extrai componentes de um par codificado com 'mkpair' """
    len_x = int.from_bytes(xy[:2], 'little')
    x = xy[2:len_x+2]
    y = xy[len_x+2:]
    return x, y

class message:
    def __init__(self, sID=None, ca=None, rID=None, act=None, s=None, c=None, ass=None):
        if all(arg is None for arg in (sID, ca, rID, act, s, c, ass)):
            # If all arguments are None, set default values
            self.senderID = ""
            self.senderCA = ""
            self.reciverID = ""
            self.action = ""
            self.subject = ""
            self.content = ""
            self.contentsign = ""
        else:
            # Initialize with provided arguments
            self.senderID = sID
            self.senderCA = ca
            self.reciverID = rID
            self.action = act
            self.subject = s
            self.content = c
            self.contentsign = ass
    
    def generate(self):
        message = {
            'SenderID': self.senderID,
            'senderCA': self.senderCA,
            'ReceiverID': self.reciverID,
            'Action': self.action,
            'Subject': self.subject,
            'Content': self.content,
            'ContentSign': self.contentsign
        }
        return message

    #limitado a 1000 bytes
    def JSONinjectionValidation(self):
        i = 0
        for item in [self.senderID, self.senderCA, self.reciverID, self.action, self.subject, self.content, self.contentsign]:
            if not isinstance(item, str):
                print(item,i)
                raise ValueError("Todos os argumentos devem ser strings")
            i+=1
            item = escape_special_characters(item)

    def encrypt_content(self, contentReceiverPK,private_key):
        self.content = encrypt(self.content.encode('utf-8'), contentReceiverPK).decode('utf-8')
        # Assinatura do content
        self.contentsign = Sign(self.content.encode('utf-8'), private_key)

    def decrypt_content(self, mySK,sender_pk):
        valid = Verify(self.contentsign.encode('utf-8'), self.content.encode('utf-8'), sender_pk)
        self.content = decrypt(self.content.encode('utf-8'), mySK).decode('utf-8')
        return valid
        
    def serialize(self, server_pk, private_key):
        self.content = encrypt(self.content.encode('utf-8'), server_pk).decode('utf-8')
        self.senderCA = self.senderCA.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
        self.JSONinjectionValidation()
        message = self.generate()
        
        serialized_msg = json.dumps(message)
        # encrypt do msg_bytes
        msg_bytes = base64.b64encode(serialized_msg.encode('utf-8'))
        # msg_bytes = serialized_msg.encode('utf-8')
        cipher = encrypt(msg_bytes, server_pk)
        # Assinatura da mensagem
        msgSign = Sign(cipher, private_key)
        # concatenar a assinatura com a cifra
        return mkpair(msgSign.encode('utf-8'), cipher)

    def deserialize(self, cipher, mySK):
        msgsign, cipher_msg = unpair(cipher)
        #decrypt da mensagem 
        msg_bytes = decrypt(cipher_msg, mySK)
        #Convert to JSON
        serialized_msg = base64.b64decode(msg_bytes.decode('utf-8'))
        message_dict = json.loads(serialized_msg)
        # Atribuir os valores do dicionário aos atributos 'self'
        self.senderID = message_dict['SenderID']
        self.senderCA = message_dict['senderCA']
        self.reciverID = message_dict['ReceiverID']
        self.action = message_dict['Action']
        self.subject = message_dict['Subject']
        self.content = decrypt(message_dict['Content'].encode('utf-8'), mySK).decode('utf-8')
        self.contentsign = message_dict['ContentSign']
        
        # Verificar JSON injection
        self.JSONinjectionValidation()
        self.senderCA = x509.load_pem_x509_certificate( self.senderCA.encode('utf-8'), default_backend())
        # decrypt_content
        #message = self.generate()
        sender_pk = self.senderCA.public_key()
        return Verify(msgsign, cipher_msg, sender_pk)
    
    def print(self):
        msg = self.generate()
        print("Message:")
        print("  Sender ID:", msg['SenderID'])
        print("  Sender CA:", msg['senderCA'])
        print("  Receiver ID:", msg['ReceiverID'])
        print("  Action:", msg['Action'])
        print("  Subject:", msg['Subject'])
        print("  Content:", msg['Content'])
        print("  Content Signature:", msg['ContentSign'])
        print("------------------------------------------------------")
    
    def serialize_public_key(self):
        serialized_key = self.content.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.content = serialized_key.decode('utf-8')

    def deserialize_public_key(self):
        pem_bytes = self.content.encode('utf-8')
        return  serialization.load_pem_public_key(pem_bytes)
    
    def send_none_serialized(self, socket):
        msg = self.generate()
        size = len(msg)
        tamanho_codificado = size.to_bytes(4, byteorder='big')
        mensagem_com_tamanho = tamanho_codificado + msg
        socket.sendall(mensagem_com_tamanho)
    
    def send(self, socket, content):
        tamanho_codificado = len(content).to_bytes(4, byteorder='big')
        mensagem_com_tamanho = tamanho_codificado + content
        socket.sendall(mensagem_com_tamanho)

    def recieve(self, socket):
        size = socket.recv(4)
        try:
            tamanho_mensagem = int.from_bytes(size, byteorder='big')
            return socket.recv(tamanho_mensagem)
        except ValueError:
            self.recieve(socket)


# # Exemplo de uso

# def load_data(file, password=None):
#     with open(file, "rb") as file:
#         p12_data = file.read()
#     private_key, certificate, _ = pkcs12.load_key_and_certificates(p12_data, password)
    
#     public_key = private_key.public_key()
    
#    return private_key, public_key, certificate

"""
uid = "123456"
rid = "123455"
sender = "alice@example.com"
subject = "Olá, mundo!"
signature_b64 = b"abcdefg123456789"
action = "SMessage"
# "ANA"

sender_SK, sender_PK, sender_ca = load_data("CLI1.p12")
# "Bob"
server_SK ,server_PK , server_ca = load_data("SERVER.p12")
#"Bob"
receiver_SK, receiver_PK, receiver_ca = load_data("CLI2.p12")
content = "Conteúdo criptografado aqui..."
"""
"""
# # Exemplo de mensagem enviada do cliente 1 para o cliente 2
# # No sender client
# msg = message(uid, sender_ca, rid, action, subject, content, signature_b64)
# msg.encrypt_content(receiver_PK)
# print("\nconteudo encriptado: ", msg.content)
# serialized_message = msg.serialize(server_PK)
# print("\nMensagem serealizada e enviada pelo cliente 1: ",serialized_message)

# # #No server
# msg2 = message()
# msg2.deserialize(serialized_message, server_SK)
# print("\nMensagem recevida e deserializada no server: ")
# msg2.print()
# serialized_message2 = msg2.serialize(receiver_PK)
# print("\nMensagem serealizada e enviada pelo server ao cliente2: ",serialized_message2)


# # #No receiver client
# msg3 = message()
# msg3.deserialize(serialized_message2, receiver_SK)
# print("\nMensagem recevida e deserializada no cliente2: ")
# msg3.print()
# msg3.decrypt_content(receiver_SK)
# print("\nconteudo encriptado: ", msg3.content)


# # #teste 2 enviar a pk para o server
# print("\nTESTE 2\n")
# # No sender client
# msg4 = message(uid, sender_ca, rid, action, subject, receiver_PK, signature_b64)
# msg4.serialize_public_key()
# print("\nconteudo da msg: ", msg4.content)
# serialized_message3 = msg4.serialize(server_PK)
# print("\nMensagem serealizada e enviada pelo cliente 1: ",serialized_message3)

# #No server
msg2 = message()
msg2.deserialize(serialized_message, server_SK)
print("\nMensagem recevida e deserializada no server: ")
msg2.print()
serialized_message2 = msg2.serialize(receiver_PK)
print("\nMensagem serealizada e enviada pelo server ao cliente2: ",serialized_message2)


# #No receiver client
msg3 = message()
msg3.deserialize(serialized_message2, receiver_SK)
print("\nMensagem recevida e deserializada no cliente2: ")
msg3.print()
msg3.decrypt_content(receiver_SK)
print("\nconteudo encriptado: ", msg3.content)


# #teste 2 enviar a pk para o server
print("\nTESTE 2\n")
# No sender client
msg4 = message(uid, sender_ca, rid, action, subject, receiver_PK, signature_b64)
msg4.serialize_public_key()
print("\nconteudo da msg: ", msg4.content)
serialized_message3 = msg4.serialize(server_PK)
print("\nMensagem serealizada e enviada pelo cliente 1: ",serialized_message3)

#No server
msg5 = message()
msg5.deserialize(serialized_message3, server_SK)
print("\nMensagem recevida e deserializada no server: ")
msg5.print()
msg5.deserialize_public_key()
print("\nConteudo: ", msg5.content)
"""
