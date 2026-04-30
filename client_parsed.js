const net = require('net');
const crypto = require('crypto');

// Адрес и порт логин-сервера
const HOST = '51.83.130.113';
const PORT = 2106;

// В данном проекте (L2CAT) для расшифровки первого пакета логин-сервера
// используется СТАТИЧЕСКИЙ КЛЮЧ ОТ ИГРОВОГО СЕРВЕРА L2J
const LOGIN_KEY = Buffer.from("[;'.]94-31==-&%@!^+]", 'ascii');

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
        console.error("Запустите скрипт с флагом: node --openssl-legacy-provider client_parsed.js");
        process.exit(1);
    }

    const prevBlock = Buffer.alloc(8, 0);
    const blocksCount = Math.floor(buffer.length / 8);

    for (let i = 0; i < blocksCount; i++) {
        const start = i * 8;
        const currentCipherBlock = buffer.subarray(start, start + 8);
        
        // 1. Меняем порядок байт (Little Endian -> Big Endian) 
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

    if (!headerRead && dataBuffer.length >= 2) {
        packetSize = dataBuffer.readUInt16LE(0) - 2;
        headerRead = true;
        dataBuffer = dataBuffer.subarray(2);
        console.log(`Ожидаемый размер тела: ${packetSize} байт`);
    }

    if (headerRead && dataBuffer.length >= packetSize) {
        const packetBody = dataBuffer.subarray(0, packetSize);
        console.log(`Получено тело пакета (${packetBody.length} байт), декодируем...`);
        
        const decodedBody = Buffer.from(packetBody);
        decryptInitPacket(decodedBody);
        
        console.log("\n--- Распаковка Init пакета ---");
        const id = decodedBody.readUInt8(0);
        console.log(`Id пакета: 0x${id.toString(16).padStart(2, '0')}`);
        
        if (id === 0x00 && decodedBody.length >= 170) {
            const sessionId = decodedBody.readUInt32LE(1);
            console.log(`Session ID: 0x${sessionId.toString(16).padStart(8, '0')} (${sessionId})`);
            
            const protocol = decodedBody.readUInt32LE(5);
            console.log(`Protocol Version: 0x${protocol.toString(16).padStart(8, '0')} (${protocol})`);
            
            const rsaKey = decodedBody.subarray(9, 9 + 128);
            console.log(`RSA Public Key (128 bytes): ${rsaKey.toString('hex').substring(0, 64)}...`);
            
            const gg = decodedBody.subarray(137, 137 + 16);
            console.log(`GG (16 bytes): ${gg.toString('hex')}`);
            
            const blowfishKey = decodedBody.subarray(153, 153 + 16);
            console.log(`Новый Blowfish Key (16 bytes): ${blowfishKey.toString('hex')}`);
        } else {
            console.log("Внимание: размер пакета или Id не совпадает со стандартным Init (170+ байт).");
        }
        console.log("------------------------------\n");

        console.log("Hex дамп декодированного пакета:");
        hexDump(decodedBody);

        client.destroy();
    }
});

client.on('close', () => {
    console.log('Соединение закрыто.');
});

client.on('error', (err) => {
    console.error(`Ошибка сокета: ${err.message}`);
});