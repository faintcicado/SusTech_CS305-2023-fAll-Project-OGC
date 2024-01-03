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


def generate_symmetric_key():
    key = "generate_symmetric_key"
    key = base64.urlsafe_b64encode(key.encode())
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


def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8080))

    # Receive the public key from the server
    serialized_public_key = client_socket.recv(2048)
    server_public_key = serialization.load_pem_public_key(
        serialized_public_key, backend=default_backend())

    # Generate symmetric key for further communication
    symmetric_key = generate_symmetric_key()

    # Encrypt the symmetric key with the server's public key and send it
    encrypted_symmetric_key = encrypt_with_public_key(
        server_public_key, symmetric_key)
    client_socket.sendall(encrypted_symmetric_key)

    # Continue with symmetric encryption for further communication
    # ...

    client_socket.close()


if __name__ == "__main__":
    start_client()
