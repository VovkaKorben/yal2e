import socket
import struct
import sys

try:
    import blowfish
except ImportError:
    print("Пожалуйста, установите библиотеку blowfish: pip install blowfish")
    sys.exit(1)

IP = "51.83.130.113"
LOGIN_PORT = 2106

# Статический ключ Blowfish, вшитый в Engine.dll
STATIC_BLOWFISH_KEY = bytes([
    0x6b, 0x60, 0xcb, 0x5b, 0x82, 0xce, 0x90, 0xb1,
    0xcc, 0x2b, 0x6c, 0x55, 0x6c, 0x6c, 0x6c, 0x6c
])

def hexdump(src, length=16):
    result = []
    digits = 2
    for i in range(0, len(src), length):
        s = src[i:i+length]
        hexa = ' '.join([f"{x:02X}" for x in s])
        text = ''.join([chr(x) if 0x20 <= x < 0x7F else '.' for x in s])
        result.append(f"{i:04X}   {hexa:<{length*(digits + 1)}}   {text}")
    return '\n'.join(result)

def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def decrypt_blowfish_l2(data, key):
    # Lineage 2 использует Blowfish с порядком байт Little Endian!
    # Стандартные криптографические библиотеки часто используют Big Endian, 
    # из-за чего расшифровка ломается. Библиотека `blowfish` умеет работать с Little Endian.
    cipher = blowfish.Cipher(key, byte_order="little")
    return b"".join(cipher.decrypt_ecb(data))

def main():
    print(f"Подключение к {IP}:{LOGIN_PORT}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((IP, LOGIN_PORT))
        print("Подключено! Ожидание пакета Init...\n")
        
        # Читаем 2 байта размера пакета (Little Endian)
        length_data = recvall(s, 2)
        if not length_data:
            print("Не удалось прочитать размер пакета.")
            return
            
        packet_len = struct.unpack('<H', length_data)[0]
        print(f"Ожидаемый размер пакета (с учетом 2 байт заголовка): {packet_len} байт")
        
        # Читаем остальную часть пакета (зашифрованную)
        payload_len = packet_len - 2
        encrypted_payload = recvall(s, payload_len)
        if not encrypted_payload:
            print("Не удалось прочитать тело пакета.")
            return
            
        print("\n--- HEX DUMP ЗАШИФРОВАННОГО ПАКЕТА (c заголовком) ---")
        full_encrypted_packet = length_data + encrypted_payload
        print(hexdump(full_encrypted_packet))
        
        if len(encrypted_payload) % 8 != 0:
            print(f"\n[ВНИМАНИЕ] Размер тела пакета ({len(encrypted_payload)}) не кратен 8!")
            
        print("\nДешифруем с использованием статического Blowfish ключа (Little Endian)...")
        # Дешифруем тело пакета
        decrypted_payload = decrypt_blowfish_l2(encrypted_payload, STATIC_BLOWFISH_KEY)
        
        print("\n--- HEX DUMP РАСШИФРОВАННОГО ПАКЕТА ---")
        print(hexdump(decrypted_payload))
        
        print("\n--- РАСШИФРОВКА ПОЛЕЙ ПАКЕТА (Init 0x00) ---")
        if decrypted_payload[0] != 0x00:
            print(f"Неожиданный ID пакета: 0x{decrypted_payload[0]:02X} (ожидался 0x00)")
            return
            
        print("Packet ID: 0x00 (Init)")
        
        # Структура Init пакета для Login Server:
        # 1 byte  - id (0x00)
        # 4 bytes - session id
        # 4 bytes - protocol version
        # 128 bytes - RSA Public Key
        # 16 bytes - Unknown / GameGuard
        # 16 bytes - BlowFish key (сессионный)
        # 1 byte  - null termination
        
        offset = 1
        
        if len(decrypted_payload) >= offset + 4:
            session_id = struct.unpack('<I', decrypted_payload[offset:offset+4])[0]
            print(f"Session ID:       0x{session_id:08X} ({session_id})")
            offset += 4
            
        if len(decrypted_payload) >= offset + 4:
            protocol = struct.unpack('<I', decrypted_payload[offset:offset+4])[0]
            print(f"Protocol Version: 0x{protocol:08X} ({protocol})")
            offset += 4
            
        if len(decrypted_payload) >= offset + 128:
            rsa_key = decrypted_payload[offset:offset+128]
            print(f"RSA Public Key:   {rsa_key.hex().upper()}")
            offset += 128
            
        if len(decrypted_payload) >= offset + 16:
            unk = decrypted_payload[offset:offset+16]
            print(f"Unknown (GG?):    {unk.hex().upper()}")
            offset += 16
            
        if len(decrypted_payload) >= offset + 16:
            blowfish_key = decrypted_payload[offset:offset+16]
            print(f"BlowFish Session: {blowfish_key.hex().upper()}")
            offset += 16
            
        if len(decrypted_payload) > offset:
            remainder = decrypted_payload[offset:]
            print(f"Остаток/Паддинг:  {remainder.hex().upper()}")
            
    except Exception as e:
        print(f"Ошибка: {e}")
    finally:
        s.close()

if __name__ == '__main__':
    main()
