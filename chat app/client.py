import socket
import os
import bcrypt
from cryptography.fernet import Fernet
import getpass

def generate_key(password):
    return Fernet.generate_key()

def save_key(key, filename='encryption_key.key'):
    with open(filename, 'wb') as key_file:
        key_file.write(key)

def load_key(filename='encryption_key.key'):
    with open(filename, 'rb') as key_file:
        return key_file.read()

def encrypt_message(message, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()

def main():
    host = 'localhost'
    port = 5874

    password = getpass.getpass("Enter the password to start the chat: ")
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    key_filename = 'encryption_key.key'
    if not os.path.exists(key_filename):
        key = generate_key(hashed_password)
        save_key(key, key_filename)
    else:
        key = load_key(key_filename)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    while True:
        message = input("Enter a message: ")
        if message.lower() == "exit":
            break

        encrypted_message = encrypt_message(message, key)
        client_socket.send(encrypted_message)

        encrypted_response = client_socket.recv(1024)
        decrypted_response = decrypt_message(encrypted_response, key)
        print(f"Server response: {decrypted_response}")

    client_socket.close()

if __name__ == "__main__":
    main()
