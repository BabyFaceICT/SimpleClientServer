import socket
import time
import sqlite3
import re  # 정규 표현식을 사용하기 위해 추가
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.x509 import load_pem_x509_certificate
import os

# SQLite3 데이터베이스 초기화
def init_db():
    conn = sqlite3.connect('server_keys.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS server_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            public_key BLOB NOT NULL UNIQUE,
            aes_key BLOB NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# 공개키와 AES 키 DB에 저장
def save_keys_to_db(public_key, aes_key):
    conn = sqlite3.connect('server_keys.db')
    cursor = conn.cursor()
    
    public_key_blob = sqlite3.Binary(public_key)
    aes_key_blob = sqlite3.Binary(aes_key)
    
    cursor.execute('INSERT INTO server_keys (public_key, aes_key) VALUES (?, ?)', (public_key_blob, aes_key_blob))
    
    conn.commit()
    conn.close()

# 공개키에 해당하는 AES 키를 DB에서 가져오기
def get_aes_key_from_db(public_key):
    conn = sqlite3.connect('server_keys.db')
    cursor = conn.cursor()
    
    public_key_blob = sqlite3.Binary(public_key)
    cursor.execute('SELECT aes_key FROM server_keys WHERE public_key = ?', (public_key_blob,))
    row = cursor.fetchone()
    
    conn.close()
    
    if row:
        return row[0]
    else:
        return None

# AES 키 생성 (32바이트)
def generate_aes_key():
    #return b'12345678912345678912345678912345'
    return os.urandom(32)

# MAC 주소 형식 검증을 위한 정규 표현식
def is_mac_address(data):
    mac_pattern = re.compile(r'([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})')
    return bool(mac_pattern.fullmatch(data))

def server_program():
    init_db()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65433))
    server_socket.listen(1)

    conn, addr = server_socket.accept()
    print(f"서버: 연결됨 - {addr}")
    time.sleep(2)

    client_cert_pem = conn.recv(4096)
    print("서버: 인증서 수신 완료")
    time.sleep(2)

    # 클라이언트 인증서 검증
    client_cert = load_pem_x509_certificate(client_cert_pem, default_backend())
    print("서버: 클라이언트 인증서 로드 완료")
    conn.send(b"Server: Certificate verification successful!")
    time.sleep(2)

    # 지속적으로 데이터 수신
    while True:
        data = conn.recv(4096)
        if not data:
            print("서버: 연결이 종료되었습니다.")
            break

        try:
            # 평문으로 시도
            decoded_data = data.decode('utf-8')
            print(f"서버: 평문 데이터 수신 - {decoded_data}")
            
            # MAC 주소 형식 확인
            if is_mac_address(decoded_data):
                print("서버: 평문 데이터로 MAC 주소 수신")
                aes_key = generate_aes_key()
                public_key_pem = client_cert.public_bytes(
                    encoding=serialization.Encoding.PEM
                )
                save_keys_to_db(public_key_pem, aes_key)
                print("서버: AES 키 생성 및 저장 완료")
                conn.send(aes_key)
                print(aes_key)
                print("서버: AES 키 전송 완료")

        except UnicodeDecodeError:
            # 암호화된 데이터로 처리
            print("서버: 암호화된 데이터 수신 시도")
            aes_key = get_aes_key_from_db(client_cert.public_bytes(
                encoding=serialization.Encoding.PEM
            ))

            if aes_key:
                decrypted_data = decrypt_mac_address_aes(data, aes_key)
                encrypted_mac = decrypted_data[:-32]
                received_aes_key = decrypted_data[-32:]
                print(received_aes_key)

                # AES 키가 일치하는지 확인
                if received_aes_key == aes_key:
                    print("서버: AES 키 일치, 인증 성공")
                    print("서버: 충전중...")
                else:
                    print("서버: 인증 실패 - AES 키 불일치")
            else:
                print("서버: AES 키를 찾을 수 없습니다.")

    conn.close()

def decrypt_mac_address_aes(encrypted_data, aes_key):
    iv = encrypted_data[:16]  # IV는 처음 16바이트
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    
    # 패딩 제거
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data

if __name__ == "__main__":
    server_program()
