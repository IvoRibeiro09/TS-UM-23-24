from socket import socket, AF_INET, SOCK_STREAM, create_connection
from ssl import SSLContext, PROTOCOL_TLS_SERVER, create_default_context, CERT_NONE
import os
from cryptography.hazmat.primitives import serialization

def creat_tls_socket(ip , port, cert, privateKey):
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.bind((ip, port))
    context = SSLContext(PROTOCOL_TLS_SERVER)
    with open("aux.crt", "wb+") as file:
        certificate_1 = cert.public_bytes(encoding=serialization.Encoding.PEM)
        file.write(certificate_1)
    with open("aux.pem", "wb+") as file:
        private_key_1 = privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        file.write(private_key_1)
    context.load_cert_chain("aux.crt", "aux.pem")
    os.remove("aux.crt")
    os.remove("aux.pem")
    return client_socket, context

def join_tls_socket(host, port):
    context = create_default_context()
    context.check_hostname = False
    context.verify_mode = CERT_NONE
    sock = create_connection((host, port))
    return context.wrap_socket(sock, server_hostname=host)
    
def creat_tcp_socket(ip, port):
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.bind((ip, port))
    return server_socket

def join_tcp_socket(ip, port):
    con = socket(AF_INET, SOCK_STREAM)
    con.connect((ip, port))
    return con
        