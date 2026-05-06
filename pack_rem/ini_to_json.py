"""
0F=NpcHtmlMessage:d(MessageID)s(HTML)d(d)
"0F":{
    "name":"NpcHtmlMessage",
    "data":[
        {"type":"d","name":"MessageID"},
        {"type":"s","name":"HTML"},
        {"type":"d","name":"d"}
    ]
}

8B=AcquireSkillInfo:d(_id)d(level)d(spCost)d(Mode)d(Count:For.0004)d(type)d(itemId)d(count)d(d)
"8B":{
    "name":"AcquireSkillInfo",
    "data":[
        {"type":"d","name":"_id"},
        {"type":"d","name":"level"},
        {"type":"d","name":"spCost"},
        {"type":"d","name":"Mode"},
        {"type":"d","name":"Count","repeat":4},
        {"type":"d","name":"type"},
        {"type":"d","name":"itemId"},
        {"type":"d","name":"count"},
        {"type":"d","name":"d"}
    ]
}


"""

import json
import os
import re

def parse_format_string(fmt_str):
    # Регулярка ловит тип переменной (буква или дефис) и содержимое скобок
    pattern = re.compile(r'([a-zA-Z-])\(([^)]+)\)')
    parsed_data = []
    
    for match in pattern.finditer(fmt_str):
        v_type = match.group(1)
        inner = match.group(2)
        
        # Ищем маркер повторения, например :For.0004 или :for.0002
        repeat_match = re.search(r':(?i:For)\.(\d+)', inner)
        if repeat_match:
            name_part = inner[:repeat_match.start()]
            repeat_val = int(repeat_match.group(1)) # Превращаем '0004' в 4
            parsed_data.append({
                "type": v_type,
                "name": name_part,
                "repeat": repeat_val
            })
        else:
            # Отрезаем дополнительную инфу (типа :Get.Func01)
            name_part = inner.split(":")[0]
            parsed_data.append({
                "type": v_type,
                "name": name_part
            })
            
    return parsed_data


def parse_ini_to_json(input_file, output_file):
    server_packets = {}
    in_server_section = False

    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            # Отрезаем комментарии (всё что после //)
            if "//" in line:
                line = line.split("//")[0].strip()

            # Пропускаем пустые строки
            if not line:
                continue

            # Отслеживаем секции (нас интересует только [server])
            if line.startswith("["):
                if line == "[server]":
                    in_server_section = True
                else:
                    in_server_section = False
                continue

            # Если мы внутри [server] и это строка с пакетом
            if in_server_section and "=" in line:
                # Разбиваем по первому знаку '='
                opcode, rest = line.split("=", 1)
                opcode = opcode.strip()
                rest = rest.strip()

                # Разбиваем правую часть по первому ':' (ИмяПакет:Формат)
                if ":" in rest:
                    name, fmt = rest.split(":", 1)
                else:
                    name, fmt = rest, ""

                server_packets[opcode] = {"name": name.strip(), "data": parse_format_string(fmt.strip())}

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(server_packets, f, indent=4, ensure_ascii=False)


if __name__ == "__main__":
    parse_ini_to_json("packetsInterlude.ini.txt", "server_packets.json")
