import socket
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
import os

def generate_secret_key(plaintext):
    salt = os.urandom(16)  # 랜덤한 salt 생성
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(plaintext.encode()), salt

def server_program():
    existing_keys = []

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))
    server_socket.listen(1)

    conn, addr = server_socket.accept()
    print(f"서버: 연결됨 - {addr}")
    time.sleep(2)

    client_cert_pem = conn.recv(4096)
    print("서버: 인증서 수신 완료")
    time.sleep(2)

    client_cert = load_pem_x509_certificate(client_cert_pem, default_backend())
    print("서버: 클라이언트 인증서 로드 완료")
    conn.send(b"Server: Certificate verification successful!")
    time.sleep(2)

    fake_mac = conn.recv(4096).decode()
    print(f"서버: 가짜 MAC 수신 - {fake_mac}")
    time.sleep(2)

    secret_key, salt = generate_secret_key(fake_mac)
    print(f"서버: 비밀키 생성 완료 - 길이: {len(secret_key)}")
    existing_keys.append(secret_key)
    time.sleep(2)

    conn.send(secret_key + salt)
    time.sleep(2)

    encrypted_mac = conn.recv(4096)
    print(f"서버: 암호화된 MAC 주소 수신 - {encrypted_mac.hex()}")
    time.sleep(2)

    conn.close()

if __name__ == "__main__":
    server_program()
