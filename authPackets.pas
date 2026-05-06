unit authPackets;
interface
uses    SysUtils, laClasses, packetUtils;
procedure AuthHandler(FEngine: TEngine; const data: TBytes);
implementation


function bf_crypt(const key: tbytes;const  payload: tbytes; decrypt: bool) :tbytes:
    if (length(payload) & $7) <> 0 then 
    raise Exception.Create('blowfish payload must be multiple of 8');
        
    c = Blowfish.new(key, Blowfish.MODE_ECB)
    fn = c.decrypt if decrypt else c.encrypt
    return b"".join(_wordswap8(fn(_wordswap8(payload[i : i + 8]))) for i in range(0, len(payload), 8))




type    TPacketHandler = procedure(const engine: TEngine; var reader: TPacketReader);



init = decrypt_login_init(rp)


procedure acInit(const engine: TEngine; var reader: TPacketReader); // 0x00
var
    SessionID, ProtocolVersion: uint32;
begin
    SessionID := reader.GetD;
    ProtocolVersion := reader.GetD;

    // Дальше читаем RSA ключ (128 байт), сохраняем их в engine 
    // и отправляем серверу RequestAuthLogin...
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

end.