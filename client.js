const net = require('net');
const crypto = require('crypto');

// Адрес и порт логин-сервера
const HOST = '51.83.130.113';
const PORT = 2106;

// Стандартный ключ Blowfish для первого пакета Login-сервера (Interlude)
const LOGIN_KEY = Buffer.from([
    0x6b, 0x60, 0xcb, 0x5b, 0x82, 0xce, 0x90, 0xb1,
    0xcc, 0x2b, 0x6c, 0x55, 0x6c, 0x6c, 0x6c, 0x6c
]);

function hexDump(buffer) {
    console.log('-'.repeat(70));
    for (let i = 0; i < buffer.length; i += 16) {
        const chunk = buffer.subarray(i, i + 16);
        const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ');
        const ascii = Array.from(chunk).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
        console.log(`${i.toString(16).padStart(8, '0')}  ${hex.padEnd(48, ' ')}  ${ascii}`);
    }
    console.log('-'.repeat(70));
}

function decryptInitPacket(buffer) {
    let decipher;
    try {
        decipher = crypto.createDecipheriv('bf-ecb', LOGIN_KEY, '');
        decipher.setAutoPadding(false);
    } catch (e) {
        console.error("Ошибка инициализации Blowfish.");
        console.error("Вероятно, вы используете Node.js v17+.");
        console.error("Запустите скрипт с флагом: node --openssl-legacy-provider client.js");
        process.exit(1);
    }

    const prevBlock = Buffer.alloc(8, 0);
    const blocksCount = Math.floor(buffer.length / 8);

    for (let i = 0; i < blocksCount; i++) {
        const start = i * 8;
        const currentCipherBlock = buffer.subarray(start, start + 8);
        
        // 1. Меняем порядок байт (Little Endian -> Big Endian) 
        // L2 читает/пишет блоки как 2 числа uint32 (little-endian)
        const swappedIn = Buffer.alloc(8);
        swappedIn.writeUInt32BE(currentCipherBlock.readUInt32LE(0), 0);
        swappedIn.writeUInt32BE(currentCipherBlock.readUInt32LE(4), 4);
        
        // 2. Декодируем
        const decryptedRaw = decipher.update(swappedIn);
        
        // 3. Возвращаем порядок байт (Big Endian -> Little Endian)
        const decryptedBlock = Buffer.alloc(8);
        decryptedBlock.writeUInt32LE(decryptedRaw.readUInt32BE(0), 0);
        decryptedBlock.writeUInt32LE(decryptedRaw.readUInt32BE(4), 4);
        
        // 4. CBC-XOR: ксорим расшифрованный блок с ПРЕДЫДУЩИМ зашифрованным блоком
        for (let j = 0; j < 8; j++) {
            buffer[start + j] = decryptedBlock[j] ^ prevBlock[j];
        }
        
        // 5. Обновляем маску для следующей итерации
        currentCipherBlock.copy(prevBlock);
    }
}

const client = new net.Socket();
let headerRead = false;
let packetSize = 0;
let dataBuffer = Buffer.alloc(0);

client.connect(PORT, HOST, () => {
    console.log(`Подключено к ${HOST}:${PORT}, ждем Init пакет...`);
});

client.on('data', (data) => {
    dataBuffer = Buffer.concat([dataBuffer, data]);

    // Читаем заголовок (2 байта - размер пакета)
    if (!headerRead && dataBuffer.length >= 2) {
        packetSize = dataBuffer.readUInt16LE(0) - 2; // -2 байта самого заголовка
        headerRead = true;
        dataBuffer = dataBuffer.subarray(2);
        console.log(`Ожидаемый размер тела: ${packetSize} байт`);
    }

    // Читаем тело пакета, когда собрали нужное количество байт
    if (headerRead && dataBuffer.length >= packetSize) {
        const packetBody = dataBuffer.subarray(0, packetSize);
        console.log(`Получено тело пакета (${packetBody.length} байт), декодируем...`);
        
        // Копируем буфер, чтобы безопасно модифицировать его
        const decodedBody = Buffer.from(packetBody);
        
        if (decodedBody.length % 8 !== 0) {
            console.log("Внимание: размер пакета не кратен 8 байтам, возможна ошибка декодирования!");
        }
        
        // Расшифровываем
        decryptInitPacket(decodedBody);
        
        // Проверяем первый байт (Id пакета Init обычно 0x00)
        console.log("Декодированный пакет:");
        hexDump(decodedBody);

        client.destroy(); // Завершаем соединение после первого пакета
    }
});

client.on('close', () => {
    console.log('Соединение закрыто.');
});

client.on('error', (err) => {
    console.error(`Ошибка сокета: ${err.message}`);
});
