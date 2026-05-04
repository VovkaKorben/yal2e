import socket
import struct
from Crypto.Cipher import Blowfish
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

# === НАСТРОЙКИ ===
HOST = "51.83.130.113"
PORT = 2106
LOGIN = 'my_login'
PASSWORD = 'my_password'

# Статический ключ Blowfish, жестко прописанный в L2Net/Code/Crypting/Blowfish.cs
STATIC_KEY = b'\x6b\x60\xcb\x5b\x82\xce\x90\xb1\xcc\x2b\x6c\x55\x6c\x6c\x6c\x6c'

def hexdump(data, label):
    print(f"\n--- {label} ({len(data)} bytes) ---")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_val = ' '.join(f"{b:02x}" for b in chunk)
        ascii_val = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        print(f"{i:04x}: {hex_val:<48} {ascii_val}")

def l2_checksum(data):
    chksum = 0
    for i in range(0, len(data), 4):
        chksum ^= struct.unpack('<I', data[i:i+4])[0]
    return struct.pack('<I', chksum)

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"Connecting to {HOST}:{PORT}...")
        s.connect((HOST, PORT))

        # 1. Получаем Init (0x00)
        raw_len = s.recv(2)
        if not raw_len: return
        p_len = struct.unpack('<H', raw_len)[0]
        payload = s.recv(p_len - 2)
        hexdump(payload, "Raw Init Packet")

        # 2. Дешифровка статическим ключом (пропускаем первый байт ID)
        cipher_st = Blowfish.new(STATIC_KEY, Blowfish.MODE_ECB)
        dec_body = cipher_st.decrypt(payload[1:])
        hexdump(dec_body, "Decrypted Init Body")

        # 3. Извлечение данных (смещения согласно L2Net LoginServer.cs)
        session_id = dec_body[0:4]
        rsa_modulus = dec_body[8:136] # 128 байт модуля
        dyn_key = dec_body[152:168]   # 16 байт нового ключа Blowfish

        # 4. RSA Шифрование
        # Модуль в L2 передается в Little-Endian, для RSA нужен Big-Endian
        mod_int = int.from_bytes(rsa_modulus, byteorder='little')
        pub_key = RSA.construct((mod_int, 65537))
        cipher_rsa = PKCS1_v1_5.new(pub_key)

        # Формируем блок для шифрования (128 байт)
        rsa_block = bytearray(128)
        rsa_block[0x5E:0x5E+len(LOGIN)] = LOGIN.encode()
        rsa_block[0x6C:0x6C+len(PASSWORD)] = PASSWORD.encode()
        encrypted_rsa = cipher_rsa.encrypt(bytes(rsa_block))

        # 5. Сборка RequestAuthLogin (0x08 в L2Net)
        auth_req = bytearray([0x08])
        auth_req.extend(encrypted_rsa)
        auth_req.extend(struct.pack('<I', 0)) # Смещения для доп. данных
        auth_req.extend(struct.pack('<I', 0))
        
        # Контрольная сумма и выравнивание
        auth_req.extend(l2_checksum(auth_req))
        while len(auth_req) % 8 != 0: auth_req.append(0)

        # 6. Шифрование динамическим ключом
        cipher_dyn = Blowfish.new(dyn_key, Blowfish.MODE_ECB)
        enc_auth = cipher_dyn.encrypt(bytes(auth_req))
        
        final_packet = struct.pack('<H', len(enc_auth) + 2) + enc_auth
        hexdump(final_packet, "Sending RequestAuthLogin")
        s.sendall(final_packet)

        # 7. Ответ сервера
        resp_len_raw = s.recv(2)
        if resp_len_raw:
            r_len = struct.unpack('<H', resp_len_raw)[0]
            resp_payload = s.recv(r_len - 2)
            dec_resp = cipher_dyn.decrypt(resp_payload)
            hexdump(dec_resp, "Final Server Response")

if __name__ == "__main__":
    main()