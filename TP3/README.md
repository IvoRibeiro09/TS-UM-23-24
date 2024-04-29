## Relatório PD1
[Relatório PD1](Projeto_de_Desenvolvimento_1_Engenharia_de_Segurança.pdf)

## Abordagem prática da aplicação

As aplicações desenvolvidas são de fácil maneio porem deixamos aqui um guia de utilização para que seja possível aos utilizadores não familiarizados conseguirem usufruir do nosso sistema.

Para uso de ambas as aplicações é necessário que na diretoria do executável esteja presente o certificado do servidor (denominado com "SERVER.crt") e, adicionalmente para usufruir da aplicação cliente, é necessário que esteja também presente tanto o certificado do cliente que irá iniciar sessão.

Assim para usufruir da aplicação servidor basta correr o comando: *"python3 server.py"*

Enquanto que para usufruir da aplicação cliente é necessário correr o comando: *"python3 Cliente.py"* e realizar o processo de autenticação como consta na figura 1.


![figura 1](Cliente_login.png)
