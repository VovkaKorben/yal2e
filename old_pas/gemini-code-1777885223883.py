import socket
import struct
from Crypto.Cipher import Blowfish
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

# Константы для подключения
HOST = "51.83.130.113"
PORT = 2106
LOGIN = "my_login"
PASSWORD = "my_password"


def hexdump(src, packet_name="Unknown Packet", length=16):
    """Выводит данные в виде шестнадцатеричной таблицы с ASCII-расшифровкой."""
    print(f"\n[+] --- {packet_name} ({len(src)} bytes) ---")
    if not src:
        print("<пустой пакет>")
        return
    for i in range(0, len(src), length):
        chunk = src[i : i + length]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        text_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        print(f"{i:04X}   {hex_str:<{length*3}}   {text_str}")
    print("-" * 50)


def append_checksum(packet: bytearray):
    """Добавляет контрольную сумму L2 к пакету."""
    chksum = 0
    for i in range(0, len(packet), 4):
        chksum ^= struct.unpack("<I", packet[i : i + 4])[0]
    packet.extend(struct.pack("<I", chksum))


def pad_packet(packet: bytearray, block_size: int = 8):
    """Дополняет пакет нулями до размера блока (для Blowfish)."""
    padding_len = block_size - (len(packet) % block_size)
    if padding_len != block_size:
        packet.extend(b"\x00" * padding_len)


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        print(f"Подключение к {HOST}:{PORT}...")
        s.connect((HOST, PORT))

        # Чтение длины первого пакета (2 байта)
        length_data = s.recv(2)
        if not length_data:
            print("Сервер разорвал соединение.")
            return

        packet_len = struct.unpack("<H", length_data)[0]

        # Чтение тела первого пакета (Init)
        init_packet = s.recv(packet_len - 2)
        hexdump(init_packet, "Init Packet (0x00)")

        if init_packet[0] != 0x00:
            print("Ошибка: ожидался пакет Init (0x00)")
            return

        # Парсинг пакета Init
        session_id = init_packet[1:5]
        protocol_version = init_packet[5:9]
        rsa_key_bytes = init_packet[9:137]
        blowfish_key = init_packet[153:169]

        print(f"Session ID: {session_id.hex()}")
        print(f"Blowfish Key: {blowfish_key.hex()}")

        # Создание ключа RSA из полученных данных (Scrambled Modulus)
        # В реальном клиенте ключ дескрэмблируется, здесь для примера нужен этот этап,
        # но для упрощения скрипта предполагаем базовый формат RSA.
        rsa_key = RSA.construct((int.from_bytes(rsa_key_bytes, byteorder="little"), 65537))
        cipher_rsa = PKCS1_v1_5.new(rsa_key)

        # Формирование блока логина и пароля для RSA шифрования (128 байт)
        # Формат: логин (14 байт), пароль (16 байт), остальное нули и константы
        login_block = bytearray(128)
        login_bytes = LOGIN.encode("utf-8")[:14]
        pass_bytes = PASSWORD.encode("utf-8")[:16]

        login_block[0x5E : 0x5E + len(login_bytes)] = login_bytes
        login_block[0x6C : 0x6C + len(pass_bytes)] = pass_bytes

        encrypted_login_block = cipher_rsa.encrypt(bytes(login_block))

        # Формирование пакета RequestAuthLogin (0x0B)
        auth_packet = bytearray()
        auth_packet.append(0x0B)
        auth_packet.extend(encrypted_login_block)
        auth_packet.extend(b"\x00" * 16)  # Место для дополнительных данных/резерв

        # Добавление чексуммы и паддинга
        append_checksum(auth_packet)
        pad_packet(auth_packet)

        # Шифрование пакета полученным Blowfish ключом
        cipher_bf = Blowfish.new(blowfish_key, Blowfish.MODE_ECB)
        encrypted_auth = cipher_bf.encrypt(bytes(auth_packet))

        # Добавляем длину пакета (длина = заголовок 2 байта + тело)
        final_packet = struct.pack("<H", len(encrypted_auth) + 2) + encrypted_auth

        hexdump(final_packet, "RequestAuthLogin (Encrypted)")
        s.send(final_packet)

        # Чтение ответа сервера (LoginOk или LoginFail)
        ans_len_data = s.recv(2)
        if ans_len_data:
            ans_len = struct.unpack("<H", ans_len_data)[0]
            ans_packet = s.recv(ans_len - 2)

            # Дешифровка ответа (Blowfish)
            decrypted_ans = cipher_bf.decrypt(ans_packet)
            hexdump(decrypted_ans, "Server Response (Decrypted)")

            if decrypted_ans[0] == 0x03:
                print("Успешная авторизация (LoginOk)!")
            elif decrypted_ans[0] == 0x01:
                reason = struct.unpack("<I", decrypted_ans[1:5])[0]
                print(f"Ошибка авторизации (LoginFail). Код причины: {reason}")

    except Exception as e:
        print(f"Произошла ошибка: {e}")
    finally:
        s.close()
        print("Соединение закрыто.")


if __name__ == "__main__":
    main()
