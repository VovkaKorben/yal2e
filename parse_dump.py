import json
import struct
import os

JSON_FILE = 'server_packets.json'
DUMP_FILE = 'packet_dump.bin'

def load_packets(json_path):
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Ошибка при чтении {json_path}: {e}")
        return {}

def main():
    if not os.path.exists(JSON_FILE):
        print(f"Файл {JSON_FILE} не найден. Сначала сгенерируйте его.")
        return
    if not os.path.exists(DUMP_FILE):
        print(f"Файл {DUMP_FILE} не найден. Убедитесь, что скрипт в движке отработал.")
        return

    packets_info = load_packets(JSON_FILE)
    packet_number = 0

    print("№ пакета / ID пакета / Длина / Название пакета")
    print("-" * 60)

    with open(DUMP_FILE, 'rb') as f:
        while True:
            # Читаем 12 байт заголовка: PckID (4), PckId2 (4), PckSize (4)
            header = f.read(12)
            if not header or len(header) < 12:
                break  # Конец файла
            
            pck_id, pck_id2, pck_size = struct.unpack('<III', header)
            
            # Читаем данные пакета длиной PckSize
            payload = f.read(pck_size)
            if len(payload) < pck_size:
                break  # Неполные данные, обрыв файла
                
            packet_number += 1
            
            if pck_size > 0:
                # Первый байт — это всегда основной Opcode пакета
                b1 = payload[0]
                op_hex = f"{b1:02X}"
                
                # Обработка двойных опкодов для расширенных пакетов (например, FE 01 00 -> FE01)
                if op_hex in ['39', 'D0', 'FE'] and pck_size >= 3:
                    sub_id = struct.unpack('<H', payload[1:3])[0]
                    op_hex = f"{b1:02X}{sub_id:02X}"
                    
                packet_name = packets_info.get(op_hex, {}).get("name", "Unknown")
                print(f"{packet_number} / {op_hex} / {pck_size} / {packet_name}")

if __name__ == '__main__':
    main()