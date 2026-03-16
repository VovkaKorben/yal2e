import socket
from Crypto.Cipher import Blowfish
import struct

use_stored = True

L2CAT_IP = "51.83.130.113"
L2CAT_LOGIN_PORT = 2106
L2CAT_GAME_PORT = 7785
FILENAME = "DUMP.BIN"
BLOWFISH_KEY = b"[;'.]94-31==-&%@!^+]"

# _cipher_state = Blowfish.new(BLOWFISH_KEY, Blowfish.MODE_ECB)


def hexdump(data):
    if not data:
        print("Данные отсутствуют.")
        return
    print("-" * 150)
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_list = [f"{b:02x}" for b in chunk]

        # HEX-часть: два блока по 8 байт
        hex_left = " ".join(hex_list[:8])
        hex_right = " ".join(hex_list[8:])

        # ASCII-часть: заменяем непечатные символы на точки и ставим пробел посередине
        ascii_left = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk[:8])
        ascii_right = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk[8:])

        # Форматированный вывод
        # :23 — ширина для 8 байт (8*2 знака + 7 пробелов)
        print(f"{i:08x}  {hex_left:23}  {hex_right:23}   {ascii_left} {ascii_right}")
    print("-" * 150)


# Пример вызова для Вашего файла:
# hexdump(raw_content)


def recv_all(sock, n):
    """Вспомогательная функция для чтения ровно n байт."""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None  # Соединение закрыто до завершения чтения
        data.extend(packet)
    return data


def sock_read():
    raw_data = None
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Установка соединения (принимает кортеж!)
        client_socket.connect((L2CAT_IP, L2CAT_LOGIN_PORT))
        print(f"Успешное подключение к {L2CAT_IP}:{L2CAT_LOGIN_PORT}")

        header = recv_all(client_socket, 2)
        if header:
            packet_size = int.from_bytes(header, byteorder="little") - 2
            print(f"Ожидаемый размер данных: {packet_size} байт")

            # 3. Читаем тело пакета на основе полученного размера
            raw_data = recv_all(client_socket, packet_size)

            if raw_data:
                print(f"Данные получены успешно. Размер: {len(raw_data)}")
                # Здесь можно приступать к обработке raw_data
            else:
                print("Ошибка: соединение разорвано при чтении тела пакета.")
        else:
            print("Ошибка: соединение разорвано при чтении заголовка.")
    except ConnectionRefusedError:
        print("Ошибка: Сервер отклонил подключение или недоступен.")
    except socket.timeout:
        print("Ошибка: Время ожидания подключения истекло.")
    # Добавлено: перехват общих ошибок сокета (разрыв связи, сброс и т.д.)
    except socket.error as e:
        print(f"Сетевая ошибка при передаче данных: {e}")
    except Exception as e:
        print(f"Непредвиденная ошибка: {e}")
    finally:
        client_socket.close()
    return raw_data


def data_write(filename, data):
    try:
        # Используем режим 'wb' (запись бинарных данных)
        with open(filename, "wb") as binary_file:
            binary_file.write(data)
        print(f"Данные успешно сохранены в {filename}")

    except IOError as e:
        print(f"Ошибка при работе с файлом: {e}")


def decrypt_init_packet(buffer):
    size = len(buffer)
    prev_block = bytes(8)

    for i in range(size // 8):
        start = i * 8
        end = start + 8

        current_block = bytes(buffer[start:end])

        # Используем существующую структуру дешифрации
        decrypted_block = _cipher_state.decrypt(current_block)

        for j in range(8):
            buffer[start + j] = decrypted_block[j] ^ prev_block[j]

        prev_block = current_block


def file_read(filename):
    raw_content = None
    try:
        with open(filename, "rb") as f:
            raw_content = bytearray(f.read())
    except FileNotFoundError:
        print(f"Файл {filename} не найден.")
    except Exception as e:
        print(f"Ошибка при обработке: {e}")
    return raw_content

def decrypt_init_packet_final(buffer):
    # Тот самый ключ из исходников L2J (LoginCrypt.ts)
    # В 99% случаев для Init пакета используется именно он
    L2J_LOGIN_KEY = b'\x6b\x60\xcb\x5b\x82\xce\x90\xb1\xcc\x2b\x6c\x55\x6c\x6c\x6c\x6c'
    
    # Инициализация Blowfish. Ключ здесь НЕ крутим, он подается как есть.
    cipher = Blowfish.new(L2J_LOGIN_KEY, Blowfish.MODE_ECB)
    
    size = len(buffer)
    prev_block = bytes(8)
    
    for i in range(size // 8):
        start = i * 8
        end = start + 8
        
        # Сохраняем текущий зашифрованный блок (для цепочки XOR)
        current_cipher_block = bytes(buffer[start:end])
        
        # 1. Читаем 8 байт как два Little-Endian uint32 (как делает Delphi/C++)
        # и упаковываем их в Big-Endian для стандартного Blowfish Питона
        l, r = struct.unpack('<II', current_cipher_block)
        block_to_decrypt = struct.pack('>II', l, r)
        
        # 2. Дешифруем блок
        decrypted_raw = cipher.decrypt(block_to_decrypt)
        
        # 3. Разворачиваем результат обратно в Little-Endian
        l_dec, r_dec = struct.unpack('>II', decrypted_raw)
        decrypted_block = struct.pack('<II', l_dec, r_dec)
        
        # 4. XOR дешифрованного блока с ПРЕДЫДУЩИМ зашифрованным (CBC)
        for j in range(8):
            buffer[start + j] = decrypted_block[j] ^ prev_block[j]
            
        # 5. Обновляем маску для следующего блока
        prev_block = current_cipher_block

def diagnostic_decrypt(raw_data):
    # Тот самый ключ из L2J Hex
    key = BLOWFISH_KEY
    # key = b'\x6b\x60\xcb\x5b\x82\xce\x90\xb1\xcc\x2b\x6c\x55\x6c\x6c\x6c\x6c'
    
    # Вариант 1: Твой v3 (Data Swap + CBC) - он дал 00 в начале, но мусор дальше
    # Вариант 2: Data Swap + НЕТ XOR (Чистый ECB)
    # Вариант 3: НЕТ Swap + НЕТ XOR (Стандартный Blowfish)

    for mode in ['v3_cbc', 'ecb_swapped', 'ecb_simple']:
        buf = bytearray(raw_data)
        cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        prev_block = bytes(8)
        
        for i in range(len(buf) // 8):
            start, end = i * 8, i * 8 + 8
            block = bytes(buf[start:end])
            
            if mode == 'ecb_simple':
                dec = cipher.decrypt(block)
            else:
                # Кувырок данных (L2 стандарт)
                l, r = struct.unpack('<II', block)
                dec = cipher.decrypt(struct.pack('>II', l, r))
                l_d, r_d = struct.unpack('>II', dec)
                dec = struct.pack('<II', l_d, r_d)
            
            if mode == 'v3_cbc':
                for j in range(8): buf[start+j] = dec[j] ^ prev_block[j]
                prev_block = block
            else:
                buf[start:end] = dec
        
        print(f"\nРЕЗУЛЬТАТ МЕТОДА: {mode}")
        # Ищем наш протокол 746 (ea 02 00 00)
        if b'\xea\x02\x00\x00' in buf:
            print("!!! НАШЕЛ 746 !!!")
        hexdump(buf[:32]) # Выводим первые пару строк для проверки

# Запуск диагностики
data_to_test = bytes.fromhex('ad 36 0a e0 f2 bd 2e 50 48 61 c3 87 3f fb fc 9c')
diagnostic_decrypt(data_to_test)

if use_stored:
    data = file_read(FILENAME)
    hexdump(data)
    decrypt_init_packet_final(data)
    hexdump(data)
else:
    data = sock_read()
    if data:
        data_write(FILENAME, data)
