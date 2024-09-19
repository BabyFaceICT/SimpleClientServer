import socket
import random
import time
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
from cryptography import x509
import os

# SQLite3 데이터베이스 초기화
def init_db(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS client_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            public_key BLOB NOT NULL UNIQUE,
            count INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# 공개키 DB에 저장
def save_key_to_db(db_path, public_key):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 공개키를 저장하기 위해 BLOB 형태로 변환
    public_key_blob = sqlite3.Binary(public_key)
    
    cursor.execute('SELECT count FROM client_keys WHERE public_key = ?', (public_key_blob,))
    row = cursor.fetchone()
    
    if row:
        count = row[0] + 1
        cursor.execute('UPDATE client_keys SET count = ? WHERE public_key = ?', (count, public_key_blob))
    else:
        count = 1
        cursor.execute('INSERT INTO client_keys (public_key, count) VALUES (?, ?)', (public_key_blob, count))
    
    conn.commit()
    conn.close()
    return count

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

def generate_random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )

def client_program(db_path):
    # 데이터베이스 초기화
    init_db(db_path)

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
        # 가짜 MAC 주소 생성 및 전송 (랜덤), 평문으로 전달
        fake_mac = generate_random_mac()
        print(f"클라이언트: 가짜 MAC 전송 중 - {fake_mac}")
        client_socket.send(fake_mac.encode())
        time.sleep(2)

        # 서버로부터 AES 키 수신
        aes_key = client_socket.recv(4096)
        print(aes_key)
        if len(aes_key) != 32:
            raise ValueError("Received AES key is of incorrect size")
        
        print(f"클라이언트: 서버로부터 AES 키 수신 완료")

        # AES 키를 DB에 저장하고 카운트 증가
        #count = save_key_to_db(db_path, aes_key)
        #print(f"클라이언트: AES 키 저장 및 카운트 업데이트 - {count}")

        for i in range(3):
            # MAC 주소 결정: 3번은 같은 MAC
            mac_address = b"00:1A:2B:3C:4D:5E:FF:FE"  # 같은 MAC 주소 (bytes로 변환)

            # 1단계: MAC 주소를 AES 키로 암호화
            encrypted_mac = encrypt_mac_address_aes(mac_address, aes_key)

            # 2단계: AES 키를 결합
            combined_data = encrypted_mac + aes_key
            print(aes_key)

            # 3단계: 결합된 데이터를 다시 AES 키로 암호화
            double_encrypted_data = encrypt_mac_address_aes(combined_data, aes_key)
            count = save_key_to_db(db_path, aes_key)
            print(f"클라이언트: 최종 암호화된 데이터 전송 중 - {double_encrypted_data.hex()} (카운트: {count})")
            
            # 암호화된 데이터 전송
            client_socket.sendall(double_encrypted_data)
            time.sleep(2)

    client_socket.close()

def encrypt_mac_address_aes(data, aes_key):
    iv = os.urandom(16)  # AES는 16바이트의 IV를 사용
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # PKCS7 패딩 적용
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data  # IV와 암호문을 함께 전송

if __name__ == "__main__":
    # 데이터베이스 경로 지정
    db_path = "client_keys.db"
    client_program(db_path)
    