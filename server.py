import socket
import threading
import json
import hashlib
from cryptography.fernet import Fernet
import rsa


PORT = 9999
SERVER_IP = socket.gethostbyname(socket.gethostname())  # SERVER_IP = "10.0.0.100"
ADDR = (SERVER_IP, PORT)
MASSAGE_LENGTH = 1024
FORMAT = 'utf-8'
SAVE_MSG = "!SAVE"
GET_MSG = "!GET"
DISCONNECT_MSG = "!DISCONNECT"
RETURN_TO_MAIN_MENU_MSG = "!Q"
ACCESS_DATABASE = "access_passwords.json"
PASS_AND_SERVICE_DATABASE = "data.json"
HASH_FUNCTION = "SHA256"
with open("symmetric_key", "r") as symmetric_key:
    SYMMETRIC_KEY = Fernet(symmetric_key.read().encode())


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    return server


def enter_system(client_sock, server_private_key):
    while True:
        action = client_sock.recv(MASSAGE_LENGTH).decode(FORMAT)
        print(f"[ACTION] user used {action}")
        if action == "SIGN":
            sign_in(client_sock, server_private_key)
            continue
        if action == "LOG":
            return log_in(client_sock, server_private_key)
        else:
            print("ERROR")


def log_in(client_sock, server_private_key):
    while True:
        username = rsa.decrypt(client_sock.recv(MASSAGE_LENGTH), server_private_key).decode()
        data = load_json(ACCESS_DATABASE)
        if user_exist(username, data):
            client_sock.send("True".encode(FORMAT))
            password = rsa.decrypt(client_sock.recv(MASSAGE_LENGTH), server_private_key).decode(FORMAT)
            if correct_password(username, password, data):
                print(f"[PERMISSION ALLOWED] permission allowed to user {username}")
                client_sock.send("True".encode(FORMAT))
                return username
            else:
                print(f"[PERMISSION DENIED] permission denied to user {username}")
                client_sock.send("False".encode(FORMAT))
                error_msg = "incorrect password"
                client_sock.send(error_msg.encode(FORMAT))
        else:
            client_sock.send("False".encode(FORMAT))
            error_msg = f"username {username} does not exist"
            client_sock.send(error_msg.encode(FORMAT))


def sign_in(client_sock, server_private_key):
    process_complete = False
    while not process_complete:
        username = rsa.decrypt(client_sock.recv(MASSAGE_LENGTH), server_private_key).decode()
        data = load_json(ACCESS_DATABASE)
        if not user_exist(username, data):
            client_sock.send("True".encode(FORMAT))
            password = rsa.decrypt(client_sock.recv(MASSAGE_LENGTH), server_private_key).decode()
            print(f"[CREATING NEW USER] creating new user {username} with password {password}")
            add_new_user_to_access_pass_database(ACCESS_DATABASE, username, password)
            add_new_user_to_data_database(PASS_AND_SERVICE_DATABASE, username)
            process_complete = True
        else:
            client_sock.send("False".encode(FORMAT))
            error_msg = f"[ERROR MASSAGE] username {username} already exist"
            client_sock.send(error_msg.encode(FORMAT))


def load_json(file_name):
    with open(file_name) as file:
        data = json.load(file)
        return data


def add_new_user_to_access_pass_database(file_name, username, password):
    hashed_username = hashlib.new(HASH_FUNCTION)
    hashed_username.update(username.encode())
    hashed_password = hashlib.new(HASH_FUNCTION)
    hashed_password.update(password.encode())
    new_user_obj = {"username": hashed_username.hexdigest(), "password": hashed_password.hexdigest()}
    with open(file_name) as file:
        data = json.load(file)
    data["users"].append(new_user_obj)
    with open(file_name, "w") as file:
        json.dump(data, file, indent=2)


def add_new_service_and_pass_to_data_database(file_name, user, service, password):
    obj = {"service": SYMMETRIC_KEY.encrypt(
        service.encode()).decode(), "password": SYMMETRIC_KEY.encrypt(password.encode()).decode()}
    with open(file_name) as file:
        data = json.load(file)
    for index in range(len(data["users"])):
        if data["users"][index]["username"] == user:
            data["users"][index]["passwords"].append(obj)
    with open(file_name, "w") as file:
        json.dump(data, file, indent=2)


def add_new_user_to_data_database(file_name, username):
    new_user_obj = {"username": username, "passwords": []}
    with open(file_name) as file:
        data = json.load(file)
    data["users"].append(new_user_obj)
    with open(file_name, "w") as file:
        json.dump(data, file, indent=2)


def user_exist(username, data):
    hashed_username = hashlib.new(HASH_FUNCTION)
    hashed_username.update(username.encode())
    exist = False
    for user in data["users"]:
        if user["username"] == hashed_username.hexdigest():
            exist = True
    return exist


def correct_password(username, password, data):
    hashed_username = hashlib.new(HASH_FUNCTION)
    hashed_username.update(username.encode())
    hashed_password = hashlib.new(HASH_FUNCTION)
    hashed_password.update(password.encode())
    for user in data["users"]:
        if user["username"] == hashed_username.hexdigest() and user["password"] == hashed_password.hexdigest():
            return True
    return False


def handle_client(client_sock, addr, enter_system, get_pass, save_pass):
    print(f"[NEW CONNECTION] {addr} connected")
    # switch public keys with client for encrypted communication
    server_public_key, server_private_key = rsa.newkeys(2048)
    client_sock.send(server_public_key.save_pkcs1())
    client_public_key = rsa.PublicKey.load_pkcs1(client_sock.recv(2048))
    username = enter_system(client_sock, server_private_key)
    connected = True
    while connected:
        msg = client_sock.recv(MASSAGE_LENGTH).decode(FORMAT)
        if msg == SAVE_MSG:
            save_pass(client_sock, addr, username, client_public_key, server_private_key)
        elif msg == GET_MSG:
            get_pass(client_sock, addr, username, client_public_key, server_private_key)
        elif msg == DISCONNECT_MSG:
            connected = False
            print(f"[DISCONNECT] {addr} has disconnected")
        else:
            continue
    client_sock.close()


def get_user_data(data, username):
    for user in data["users"]:
        if user["username"] == username:
            return user["passwords"]
    return None


def get_pass_for_service(user_data, my_service):
    for service in user_data:
        if SYMMETRIC_KEY.decrypt(service["service"]).decode() == my_service:
            return SYMMETRIC_KEY.decrypt(service["password"]).decode()
    return False


def service_exist(user_data, my_service):
    for service in user_data:
        if SYMMETRIC_KEY.decrypt(service["service"]).decode() == my_service:
            return True
    return False


def get_pass(client_sock, addr, username, client_public_key, server_private_key):
    data = load_json(PASS_AND_SERVICE_DATABASE)
    user_data = get_user_data(data, username)
    go_to_main_menu = False
    while not go_to_main_menu:
        service = rsa.decrypt(client_sock.recv(MASSAGE_LENGTH), server_private_key).decode()
        if service == RETURN_TO_MAIN_MENU_MSG:
            go_to_main_menu = True
        elif service_exist(user_data, service):
            password = get_pass_for_service(user_data, service)
            client_sock.send("True".encode(FORMAT))
            client_sock.send(rsa.encrypt(password.encode(), client_public_key))
            go_to_main_menu = True
        else:
            error_msg = f"user {username} didn't save a password for the service '{service}'"
            client_sock.send("False".encode(FORMAT))
            client_sock.send(error_msg.encode(FORMAT))
            continue


def save_pass(client_sock, addr, user, client_public_key, server_private_key):
    data = load_json(PASS_AND_SERVICE_DATABASE)
    user_data = get_user_data(data, user)
    go_to_main_menu = False
    while not go_to_main_menu:
        service = rsa.decrypt(client_sock.recv(MASSAGE_LENGTH), server_private_key).decode()
        if service == RETURN_TO_MAIN_MENU_MSG:
            go_to_main_menu = True
        elif service_exist(user_data, service):
            client_sock.send("False".encode(FORMAT))
            error_msg = f"service '{service}' already exist in the user database"
            client_sock.send(error_msg.encode(FORMAT))
        else:
            client_sock.send("True".encode(FORMAT))
            password = rsa.decrypt(client_sock.recv(MASSAGE_LENGTH), server_private_key).decode()
            if password == RETURN_TO_MAIN_MENU_MSG:
                go_to_main_menu = True
            else:
                add_new_service_and_pass_to_data_database(PASS_AND_SERVICE_DATABASE, user, service, password)
                approval_msg = f"The password '{password}' was saved ander the service {service}"
                client_sock.send(rsa.encrypt(approval_msg.encode(), client_public_key))
                break


def start():
    server = start_server()
    server.listen()
    while True:
        client_sock, adrr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_sock, adrr, enter_system, get_pass, save_pass))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")


print("[STARTING] server is starting...")
start()
