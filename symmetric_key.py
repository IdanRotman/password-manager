from cryptography.fernet import Fernet


key = Fernet.generate_key()
with open("symmetric_key", "w") as file:
    file.write(key.decode())


