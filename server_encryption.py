from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import socket


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_with_public_key(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_with_private_key(private_key, ciphertext):
    if len(ciphertext) != private_key.key_size // 8:
        raise ValueError("Ciphertext length must be equal to key size.")
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8080))
    server_socket.listen(1)
    print("Server listening on port 8080...")

    client_socket, addr = server_socket.accept()
    print("Connection from", addr)

    # Generate key pair for asymmetric encryption
    private_key, public_key = generate_key_pair()

    # Send the public key to the client
    serialized_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.sendall(serialized_public_key)

    # Receive the encrypted symmetric key from the client
    encrypted_symmetric_key = client_socket.recv(2048)
    symmetric_key = decrypt_with_private_key(
        private_key, encrypted_symmetric_key)

    # Now you have the symmetric key for further communication
    print("Symmetric Key:", symmetric_key)
    print("Symmetric Key:", symmetric_key.decode())

    # Continue with symmetric encryption for further communication
    # ...

    server_socket.close()


if __name__ == "__main__":
    start_server()
