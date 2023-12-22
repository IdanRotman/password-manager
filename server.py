import socket
import threading

PORT = 9999
SERVER_IP = socket.gethostbyname(socket.gethostname())  # SERVER_IP = "10.0.0.100"
ADDR = (SERVER_IP, PORT)
MASSAGE_LENGTH = 1024
FORMAT = 'utf-8'
DISCONNECT_MSG = "!DISCONNECT"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)


def handle_client(client_sock, addr):
    print(f"[NEW CONNECTION] {addr} connected")
    connected = True
    while connected:
        msg = client_sock.recv(MASSAGE_LENGTH).decode(FORMAT)
        if msg:
            if msg == DISCONNECT_MSG:
                connected = False
                print(f"[DISCONNECT] {addr} has disconnected")
            else:
                print(f"[{addr}] {msg}")
    client_sock.close()


def start():
    server.listen()
    while True:
        client_sock, adrr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_sock, adrr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")


print("[STARTING] server is starting...")
start()
