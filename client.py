import socket
import rsa

SERVER_IP = socket.gethostbyname(socket.gethostname())  # ("10.0.0.100") this line works if you run both                                                       
SERVER_PORT = 9999                                      # from same computer
SERVER_ADDR = (SERVER_IP, SERVER_PORT)
MASSAGE_LENGTH = 1024
FORMAT = 'utf-8'
SAVE_MSG = "!SAVE"
GET_MSG = "!GET"
DISCONNECT_MSG = "!DISCONNECT"
RETURN_TO_MAIN_MANU_KEY = "Q"
INFORMATION_MSG = f"YOU CAN ALLWAYS RETURN TO THE MAIN MENU BY PRESSING [{RETURN_TO_MAIN_MANU_KEY}]."


# ------ assist functions ------

def send_data(client, msg, server_public_key):
    client.send(rsa.encrypt(msg.encode(), server_public_key))
    confirmation_msg = client.recv(MASSAGE_LENGTH).decode(FORMAT)                           
    return confirmation_msg == "True"


def return_to_main_manu(massage):
    return massage.upper() == RETURN_TO_MAIN_MANU_KEY

# ------ assist functions ------


def connect_client_to_server():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(SERVER_ADDR)
    return client


def enter_system(client, server_public_key):
    while True:
        action = input("DO YOU HAVE AN ACCOUNT TO LOG IN TO OR DO YOU WANT TO SIGN IN? \n"
                       "   - SIGN- to sign in \n"
                       "   - LOG-  to log in \n")
        action = action.upper()
        if action == "SIGN":
            client.send(action.encode(FORMAT))
            sign_in(client, server_public_key)
            continue
        elif action == "LOG":
            client.send(action.encode(FORMAT))
            log_in(client, server_public_key)
            break
        else:
            print("YOU DIDN'T CHOSE AN EXISTING ACTION. TRY AGAIN")


def log_in(client, server_public_key):
    process_complete = False
    while not process_complete:
        username_msg = input("Enter your username: ")
        confirmation_msg = send_data(client, username_msg, server_public_key)
        if not confirmation_msg:
            error_msg = client.recv(MASSAGE_LENGTH).decode(FORMAT)
            print(f"[ERROR MASSAGE] {error_msg}")
            continue
        password_msg = input("Enter your password: ")  
        confirmation_msg = send_data(client, password_msg, server_public_key)
        if confirmation_msg:
            break
        else:
            error_msg = client.recv(MASSAGE_LENGTH).decode(FORMAT)
            print(f"[ERROR MASSAGE] {error_msg}")
            continue


def sign_in(client, server_public_key):
    process_complete = False
    while not process_complete:
        username_msg = input("Enter your username: ")
        confirmation_msg = send_data(client, username_msg, server_public_key)
        if confirmation_msg:
            password_msg = input("Enter your password: ")  
            client.send(rsa.encrypt(password_msg.encode(), server_public_key))
            break
        else:
            error_msg = client.recv(MASSAGE_LENGTH).decode(FORMAT)
            print(f"[ERROR MASSAGE] {error_msg}")


def save_pass(client, server_public_key, client_private_key):
    print(INFORMATION_MSG)
    while True:
        service = input("Enter the name of the service you want to save a password for: ")
        if return_to_main_manu(service):
            client.send(rsa.encrypt(("!" + RETURN_TO_MAIN_MANU_KEY).encode(), server_public_key))
            break
        confirmation_msg = send_data(client, service, server_public_key)
        if not confirmation_msg:
            error_msg = client.recv(MASSAGE_LENGTH).decode(FORMAT)
            print(f"[ERROR MASSAGE] {error_msg}")
        else:
            password = input(f"Enter a password for {service}: ")
            if return_to_main_manu(password):
                client.send(rsa.encrypt(("!" + RETURN_TO_MAIN_MANU_KEY).encode(), server_public_key))
                break
            client.send(rsa.encrypt(password.encode(), server_public_key))
            approval_msg = rsa.decrypt(client.recv(MASSAGE_LENGTH), client_private_key).decode()
            print(f"[APPROVAL_MASSAGE] {approval_msg}")
            break


def get_pass(client, server_public_key, client_private_key):
    print(INFORMATION_MSG)
    while True:
        service = input("Enter the name of the service you want to get a password for: ")
        if return_to_main_manu(service):
            client.send(rsa.encrypt(("!" + RETURN_TO_MAIN_MANU_KEY).encode(), server_public_key))
            break
        confirmation_msg = send_data(client, service, server_public_key)
        if not confirmation_msg:
            error_msg = client.recv(MASSAGE_LENGTH).decode(FORMAT)
            print(f"[ERROR MASSAGE] {error_msg}")
        else:
            password = rsa.decrypt(client.recv(MASSAGE_LENGTH), client_private_key).decode() 
            print(f"The password for {service} is '{password}'")
            break


def disconnect(client):
    client.send(DISCONNECT_MSG.encode(FORMAT))


def main():
    client = connect_client_to_server()
    # which public keys with server for encrypted communication
    client_public_key, client_private_key = rsa.newkeys(2048)
    server_public_key = rsa.PublicKey.load_pkcs1(client.recv(2048))
    client.send(client_public_key.save_pkcs1())
    enter_system(client, server_public_key,)
    connected = True
    print("Wellcome to the password manager!")
    while connected:
        action = input("You can use the following actions: \n"
                        "   - Save password- SAVE \n"
                        "   - Get password- GET \n"
                        "   - Disconnect- DISCONNECT\n\n"
                        "Enter the action you want to execute: ")
        action = action.upper()
        if action == "SAVE":
            client.send(SAVE_MSG.encode(FORMAT))
            save_pass(client, server_public_key, client_private_key)
            input("Press ENTER to go back to the main menu")
        elif action == "GET":
            client.send(GET_MSG.encode(FORMAT))
            get_pass(client, server_public_key, client_private_key)
            input("Press ENTER to go back to the main menu")
        elif action == "DISCONNECT":
            client.send(DISCONNECT_MSG.encode(FORMAT))
            disconnect(client)
            connected = False
        else:
            print(f"[ERROR] {action} is an invalid input")
            continue


if __name__ == "__main__":
    main()
