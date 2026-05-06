unit authPackets;

interface

uses
    SysUtils, laClasses, packetUtils, Blowfish;

procedure AuthHandler(FEngine: TEngine; const data: TBytes);

implementation


type
    TPacketHandler = procedure(const engine: TEngine; var reader: TPacketReader);

var
    INTERLUDE_BLOWFISH_KEYS: array [0..1] of TBytes;

procedure dec_xor_pass(var data: TBytes);
var
    key, enc, plain: uint32;
    p: puint32;
    pos: integer;
begin
    if length(data) < 12 then
        raise Exception.Create('dec_xor_pass need block >= 12 bytes length');

    pos := length(data) - 8;
    key := PUint32(@data [pos])^;

    pos := length(data) - 12;

    while pos >= 4 do
    begin
        p := PUint32(@data [pos]); // Встаем на текущий блок
        enc := p^;
        plain := enc xor key;
        p^ := plain;              // Записываем расшифрованное
        key := key - plain;       // Обновляем ключ (Delphi сам отсечет лишнее по uint32)
        dec(pos, 4);
    end;
end;

function bf_crypt(const key: TBytes; const payload: TBytes; decrypt: boolean): TBytes;
var
    blowfishData: TBlowfishData;
    i: integer;
    tempPayload: TBytes;
begin
    if (length(payload) and $7) <> 0 then
        raise Exception.Create('blowfish payload must be multiple of 8');

    // Делаем копию payload, чтобы не испортить оригинальный пакет при swap8
    SetLength(tempPayload, Length(payload));
    if Length(payload) > 0 then
        Move(payload [0], tempPayload [0], Length(payload));

    setlength(result, length(payload));
    BlowfishInit(blowfishData, @key, length(key), nil);
    swap8(tempPayload);

    if decrypt then
        BlowfishDecryptECB(blowfishData, @payload [0], @result [0])
    else
        BlowfishEncryptECB(blowfishData, @payload [0], @result [0]);
    swap8(result);
end;


procedure acInit(const engine: TEngine; var reader: TPacketReader); // 0x00
var
    keyIndex: int32;
    initOk: boolean;
    decrypted: TBytes;
begin
    initOk := false;
    for keyIndex := low(INTERLUDE_BLOWFISH_KEYS) to high(INTERLUDE_BLOWFISH_KEYS) do
    begin
        decrypted := bf_crypt(INTERLUDE_BLOWFISH_KEYS [keyIndex], reader.Raw, true);
        if decrypted [0] = $00 then
        begin
            initOk := true;
            break;
        end else if Length(decrypted) >= 12 then
        begin
            dec_xor_pass(decrypted);
            if decrypted [0] = $00 then
            begin
                initOk := true;
                break;
            end;
        end;
    end;

    if not initOk then
        raise Exception.Create('Invalid auth packet 0x00');

// Заменяем reader на новый, смотрящий на РАСШИФРОВАННЫЕ данные.
    // Offset = 1, чтобы пропустить Opcode ($00)
    reader := TPacketReader.Create(decrypted, 1);

    // Теперь можно безопасно читать SessionID:
    // SessionID := reader.GetD;
end;

procedure acLoginFail(const engine: TEngine; var reader: TPacketReader); // 0x01
begin
end;

procedure acServerList(const engine: TEngine; var reader: TPacketReader); // 0x04
begin
end;

procedure acPlayFail(const engine: TEngine; var reader: TPacketReader); // 0x06
begin
end;

procedure acPlayOk(const engine: TEngine; var reader: TPacketReader); // 0x07
begin
end;

procedure acGgAuth(const engine: TEngine; var reader: TPacketReader); // 0x0B
begin
end;

const
    AuthPacketHandlers: array[0..11] of TPacketHandler = (
        acInit, // 0x00
        acLoginFail, nil, nil, // 0x01
        acServerList, nil, // 0x04
        acPlayFail,// 0x06
        acPlayOk, nil, nil, nil,// 0x07
        acGgAuth // 0x0B
        );


procedure AuthHandler(const FEngine: TEngine; const data: TBytes);
var
    packetId: uint8;
    Reader: TPacketReader;
    handler: TPacketHandler;
begin
    if Length(data) = 0 then
        raise Exception.Create('Empty auth packet');

    Reader := TPacketReader.Create(data);
    packetId := Reader.GetC;

    // Защита от выхода за границы массива (Access Violation)
    if packetId > High(AuthPacketHandlers) then
        raise Exception.CreateFmt('Unknown auth packet #%d (Out of bounds)', [packetId]);

    handler := AuthPacketHandlers [packetId];
    if not Assigned(handler) then
        raise Exception.CreateFmt('Unhandled auth packet #%d', [packetId]);

    handler(FEngine, Reader);
end;

initialization
    INTERLUDE_BLOWFISH_KEYS[0] := LoadFromRes('STATIC_BLOWFISH_KEY');
    INTERLUDE_BLOWFISH_KEYS[1] := LoadFromRes('LEGACY_STATIC_BLOWFISH_KEY');
end.