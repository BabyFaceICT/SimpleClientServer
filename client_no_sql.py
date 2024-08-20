import socket
import hashlib
import random
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
from cryptography import x509
import os

# 클라이언트 측 인증서 생성
def generate_client_certificate():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"EVCC"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"EVCC"),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()).serial_number(
        x509.random_serial_number()
    ).not_valid_before(datetime.now(timezone.utc)).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256())
    
    return private_key, cert

# 가짜 MAC 주소 생성
def generate_random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )

# 비밀키 생성
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

# AES 암호화를 사용하여 MAC 주소 암호화
def encrypt_mac_address_aes(mac_address, secret_key):
    iv = os.urandom(16)  # AES는 16바이트의 IV를 사용
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # PKCS7 패딩 적용
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(mac_address.encode()) + padder.finalize()
    
    encrypted_mac = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_mac  # IV와 암호문을 함께 전송

# 기존 비밀키가 존재하는지 확인
def check_existing_key(existing_keys, secret_key):
    for key in existing_keys:
        if key == secret_key:
            return True
    return False

# 클라이언트 프로그램 실행
def client_program():
    existing_keys = []  # 기존 비밀키를 저장할 리스트

    client_private_key, client_cert = generate_client_certificate()
    client_cert_pem = client_cert.public_bytes(encoding=serialization.Encoding.PEM)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 65432))

    print("클라이언트: 인증서 전송 중...")
    client_socket.send(client_cert_pem)
    time.sleep(2)

    response = client_socket.recv(4096)
    print("클라이언트: 서버 응답 -", response.decode())
    time.sleep(2)

    if b"Server: Certificate verification successful!" in response:
        fake_mac = generate_random_mac()
        print(f"클라이언트: 가짜 MAC 전송 중 - {fake_mac}")
        client_socket.send(fake_mac.encode())
        time.sleep(2)

        secret_key_and_salt = client_socket.recv(4096)
        if len(secret_key_and_salt) != 48:  # 32 바이트의 키 + 16 바이트의 salt
            print("클라이언트: 비밀키 및 salt 수신 오류 - 잘못된 데이터 길이")
            return

        secret_key, salt = secret_key_and_salt[:32], secret_key_and_salt[32:]
        print(f"클라이언트: 비밀키 수신 완료 - 길이: {len(secret_key)}")
        print(f"클라이언트: salt 수신 완료 - 길이: {len(salt)}")
        time.sleep(2)

        if check_existing_key(existing_keys, secret_key):
            print("클라이언트: 기존 비밀키와 일치함. MAC 암호화 준비 중...")
        else:
            print("클라이언트: 새로운 비밀키 감지, 평문으로 가짜 MAC 재전송")
            existing_keys.append(secret_key)
            client_socket.send(fake_mac.encode())
            time.sleep(2)

            secret_key_and_salt = client_socket.recv(4096)
            if len(secret_key_and_salt) != 48:  # 32 바이트의 키 + 16 바이트의 salt
                print("클라이언트: 비밀키 및 salt 재수신 오류 - 잘못된 데이터 길이")
                return

            secret_key, salt = secret_key_and_salt[:32], secret_key_and_salt[32:]
            print(f"클라이언트: 비밀키 재수신 완료 - 길이: {len(secret_key)}")
            print(f"클라이언트: salt 재수신 완료 - 길이: {len(salt)}")

        mac_address = "00:1A:2B:3C:4D:5E:FF:FE"  # 예시 MAC 주소
        encrypted_mac = encrypt_mac_address_aes(mac_address, secret_key)
        print(f"클라이언트: MAC 주소 AES 암호화 및 전송 중 - {encrypted_mac.hex()}")

        client_socket.send(encrypted_mac)
        time.sleep(2)

    client_socket.close()

    existing_keys = []  # 기존 비밀키를 저장할 리스트

    client_private_key, client_cert = generate_client_certificate()
    client_cert_pem = client_cert.public_bytes(encoding=serialization.Encoding.PEM)

    # TCP 클라이언트 소켓 설정
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 65432))

    # 서버로 인증서 전송
    print("클라이언트: 인증서 전송 중...")
    client_socket.send(client_cert_pem)
    time.sleep(2)

    # 서버의 응답 수신
    response = client_socket.recv(4096)
    print("클라이언트: 서버 응답 -", response.decode())
    time.sleep(2)

    if b"Server: Certificate verification successful!" in response:
        # 가짜 MAC 주소 생성 및 전송 (랜덤)
        fake_mac = generate_random_mac()
        print(f"클라이언트: 가짜 MAC 전송 중 - {fake_mac}")
        client_socket.send(fake_mac.encode())
        time.sleep(2)

        # 서버로부터 비밀키 수신
        secret_key_and_salt = client_socket.recv(4096)
        if len(secret_key_and_salt) != 48:  # 32 바이트의 키 + 16 바이트의 salt
            print("클라이언트: 비밀키 및 salt 수신 오류 - 잘못된 데이터 길이")
            return

        secret_key, salt = secret_key_and_salt[:32], secret_key_and_salt[32:]
        print(f"클라이언트: 비밀키 수신 완료 - 길이: {len(secret_key)}")
        print(f"클라이언트: salt 수신 완료 - 길이: {len(salt)}")
        time.sleep(2)

        # 비밀키 DB에서 동일한 키가 있는지 확인
        if check_existing_key(existing_keys, secret_key):
            print("클라이언트: 기존 비밀키와 일치함. MAC 암호화 준비 중...")
        else:
            print("클라이언트: 새로운 비밀키 감지, 평문으로 가짜 MAC 재전송")
            existing_keys.append(secret_key)  # 새로운 키 저장
            client_socket.send(fake_mac.encode())
            time.sleep(2)
            secret_key_and_salt = client_socket.recv(4096)
            if len(secret_key_and_salt) != 48:  # 32 바이트의 키 + 16 바이트의 salt
                print("클라이언트: 비밀키 및 salt 재수신 오류 - 잘못된 데이터 길이")
                return

            secret_key, salt = secret_key_and_salt[:32], secret_key_and_salt[32:]
            print(f"클라이언트: 비밀키 재수신 완료 - 길이: {len(secret_key)}")
            print(f"클라이언트: salt 재수신 완료 - 길이: {len(salt)}")

        # 실제 MAC 주소 암호화 (AES 사용)
        mac_address = "00:1A:2B:3C:4D:5E:FF:FE"  # 예시 MAC 주소
        encrypted_mac = encrypt_mac_address_aes(mac_address, secret_key)
        print(f"클라이언트: MAC 주소 AES 암호화 및 전송 중 - {encrypted_mac.hex()}")
        
        # 암호화된 MAC 주소 전송
        client_socket.send(encrypted_mac)
        time.sleep(2)

    client_socket.close()

if __name__ == "__main__":
    client_program()
