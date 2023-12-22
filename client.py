import socket

SERVER_IP = socket.gethostbyname(socket.gethostname())
SERVER_PORT = 9999
SERVER_ADDR = (SERVER_IP, SERVER_PORT)
FORMAT = 'utf-8'
DISCONNECT_MSG = "!DISCONNECT"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(SERVER_ADDR)

while True:
    msg = input("Enter a massage: ")
    if msg == "disconnect":
        client.send(DISCONNECT_MSG.encode(FORMAT))
        break
    client.send(msg.encode(FORMAT))