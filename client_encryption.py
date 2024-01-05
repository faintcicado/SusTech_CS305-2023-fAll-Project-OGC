from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import os
import base64
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets


def generate_symmetric_key():
    key = secrets.token_bytes(16)  # Generate a 128-bit (16-byte) key
    return key


def encrypt_with_public_key(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Generate symmetric key for further communication


def symmetric_encrypt(key, plaintext):
    algorithm = algorithms.ARC4(key)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode())
    return ciphertext


def symmetric_decrypt(key, ciphertext):
    algorithm = algorithms.ARC4(key)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)
    return plaintext


def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8080))
    print("Connected to server.")

    # Receive the public key from the server
    serialized_public_key = client_socket.recv(2048)
    server_public_key = serialization.load_pem_public_key(
        serialized_public_key, backend=default_backend())

    print("Public key received from server.")

    symmetric_key = generate_symmetric_key()

    # Encrypt the symmetric key with the server's public key and send it
    encrypted_symmetric_key = encrypt_with_public_key(
        server_public_key, symmetric_key)
    client_socket.sendall(encrypted_symmetric_key)
    print("Symmetric key sent to server.")

    # Continue with symmetric encryption for further communication
    # time.sleep(3)
    # Send a GET request
    request = "GET /example.txt HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic Y2xpZW50MToxMjM=\r\n\r\n"
    print(request)
    encrypted_request = symmetric_encrypt(symmetric_key, request)
    client_socket.sendall(encrypted_request)

    # Receive the response
    response = client_socket.recv(4096)
    print(response)
    decrypted_response = symmetric_decrypt(symmetric_key, response)
    print(decrypted_response)

    client_socket.close()


if __name__ == "__main__":
    start_client()
