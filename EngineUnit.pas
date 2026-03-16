unit EngineUnit;

interface

uses windows, sysutils, classes, l2packetbase, loginpackets, blowfish, winapi.winsock2;

const
    l2cat_ip = '51.83.130.113';
    l2cat_login_port = 2106;
    l2cat_game_port = 7785;

type
    tenginestate = (esError, esIdle, esLogging);
    tonpacketevent = procedure(sender: tobject; apacket: tl2packetstream) of object;

    TEngine = class;

    tsocketthread = class(tthread)
    protected
        procedure Execute; override;
    private
        FEngine: tengine;

    public
        constructor create(aengine: tengine);
    end;

    TEngine = class
    private
        FGuiMessage: string;
        flogin, fpassword: string;
        //        bfdata: tblowfishdata;
        fsocket: tsocket;
        faddr: tsockaddrin;
        fthread: tsocketthread;
        //        FSessionID: uint32;

        fonpacket: tonpacketevent;

        // Внутренние методы обработки
        procedure processincomingpacket();
        procedure handleinit(apacket: tl2packetstream);

        // procedure PacketDispatcher(APacket: TL2PacketStream);
        function connect(ip: string; port: word): boolean;
    protected
        packetStream: tl2packetstream;
    public

        state: tenginestate;

        property onpacket: tonpacketevent read fonpacket write fonpacket;

        procedure dologin();
        function packettohex(): string;
        function packettohex2(): string;
        constructor create(login, password: string);
        destructor Destroy; override;

        procedure syncstatus;
        procedure disconnect;
    end;

implementation
uses unit3;
const
    blowfishkey = '[;''.]94-31==-&%@!^+]';
                    

constructor tsocketthread.create(aengine: tengine);
begin
    inherited create(false);
    FEngine := aengine;
    freeonterminate := true;
end;

procedure tsocketthread.execute;
var
    packetSize: uint16;
    bodySize, res: int32;
    //    packet: tl2packetstream;
begin
    //    packet := tl2packetstream.create(blowfishkey);
    try
        while not terminated do
        begin
            res := recv(fengine.fsocket, packetSize, 2, 0);
            if (res <= 0) or terminated then
                break;

            bodySize := packetSize - 2;
            if bodySize <= 0 then
                continue;

            FEngine.packetStream.clear;
            FEngine.packetStream.setsize(bodySize);

            res := recv(fengine.fsocket, FEngine.packetStream.memory^, bodySize, 0);
            if (res <= 0) or terminated then
                break;

            fengine.processincomingpacket();
        end;
    finally

        FEngine.State := esError;
        tthread.synchronize(nil, fengine.syncstatus);
    end;
end;

{ TEngine }

constructor tengine.create(login, password: string);
var
    wsadata: twsadata;
begin
    inherited create;
    state := esidle;
    flogin := login;
    fpassword := password;

    wsastartup($0202, wsadata);

    packetStream := tl2packetstream.create(blowfishkey);
    fsocket := invalid_socket;

end;

destructor tengine.destroy;
begin
    disconnect;
    wsacleanup;
    packetStream.free;
    inherited;
end;

procedure tengine.disconnect;
begin

    if fsocket <> invalid_socket then
    begin
        if assigned(fthread) then
            fthread.terminate;
        closesocket(fsocket);
        fsocket := invalid_socket;
    end;

end;

procedure tengine.dologin();
begin
    //    requestauthlogin(sendpacket, flogin, fpassword);
    connect(l2cat_ip, l2cat_login_port);
end;

function tengine.connect(ip: string; port: word): boolean;
var
    connResult: int32;
    aStr: AnsiString;
begin
    result := false;
    fsocket := socket(af_inet, sock_stream, ipproto_tcp);
    if fsocket = invalid_socket then
        exit;

    faddr.sin_family := af_inet;
    faddr.sin_port := htons(port);

    aStr := AnsiString(ip);
    faddr.sin_addr.S_addr := inet_addr(PAnsiChar(aStr));

    connResult := winapi.winsock2.connect(fsocket, tsockaddr(faddr), sizeof(faddr));
    if connResult <> socket_error then
    begin
        fthread := tsocketthread.create(self);
        result := true;
        // state := asConnected;
        // Сразу после коннекта ждем Init пакет от сервера
        // Result := ReceivePacket(sendPacket);
    end
    else
    begin
        // Если не коннектится, получим код ошибки:
        OutputDebugString(PChar('Socket Error: ' + IntToStr(WSAGetLastError)));
        closesocket(fsocket);
        fsocket := invalid_socket;
        FGuiMessage := 'Socket Error: ' + IntToStr(WSAGetLastError);

        tthread.synchronize(nil, syncstatus);
    end;
end;

function tengine.packettohex(): string;
var
    i: integer;
    p: pbyte;
begin
    result := '';
    if (packetStream = nil) or (packetStream.size = 0) then
        exit;

    p := packetStream.memory;
    for i := 0 to packetStream.size - 1 do
    begin
        result := result + inttohex(p^, 2) + ' ';
        inc(p);
    end;
    result := trim(result);
end;

function tengine.packettohex2(): string;
var
    i, j: integer;
    p: pbyte;
    lineHex, lineChar: string;
    b: byte;
begin
    result := '';
    if (packetStream = nil) or (packetStream.size = 0) then
        exit;

    p := packetStream.memory;

    for i := 0 to (packetStream.size - 1) div 16 do
    begin
        lineHex := '';
        lineChar := '';

        // Смещение (адрес ряда)
        result := result + inttohex(i * 16, 4) + ': ';

        for j := 0 to 15 do
        begin
            if (i * 16 + j) < packetStream.size then
            begin
                b := p^;
                lineHex := lineHex + inttohex(b, 2) + ' ';

                // Формируем ASCII колонку (справа)
                if b in [32..126] then // Печатные символы
                    lineChar := lineChar + char(b)
                else
                    lineChar := lineChar + '.';

                inc(p);
            end
            else
            begin
                // Заполняем пустоту, если пакет закончился раньше конца строки
                lineHex := lineHex + '   ';
            end;

            // Разделитель посередине (после 8 байт) для удобства
            if j = 7 then
                lineHex := lineHex + ' ';
        end;

        result := result + lineHex + '  | ' + lineChar + sLineBreak;
    end;
end;

procedure tengine.processincomingpacket();
var
    opcode: byte;
begin
    FGuiMessage := packettohex2();

    tthread.synchronize(nil, syncstatus);

    exit;
    // Тут можно воткнуть дешифратор Blowfish, если пакет пришел от Login
    // EncryptPacket(BFData);

    opcode := packetStream.readc;

    case opcode of
        $00:
            handleinit(packetStream);
        $03:
            begin
                tthread.synchronize(nil, syncstatus);
            end;
        $01:
            begin
                tthread.synchronize(nil, syncstatus);
            end;
    end;
end;

procedure tengine.syncstatus;
begin
    if Assigned(FMainForm) then
        FMainForm.Memo1.Lines.Add(FGuiMessage);
end;

procedure tengine.handleinit(apacket: tl2packetstream);
begin

end;









const
  // Тот самый статический ключ из конфигов L2J
  L2J_STATIC_KEY = '[;''.]94-31==-&%@!^+]';

procedure DecryptInitPacket(var Buffer: array of Byte; Size: Integer);
var
  i, j: Integer;
  PrevBlock, CurrentBlock: array[0..7] of Byte;
begin
  // В L2J первый блок Init XOR-ится с "пустым" блоком (все нули)
  FillChar(PrevBlock, 8, 0);

  // Проходим по всему телу пакета блоками по 8 байт
  for i := 0 to (Size div 8) - 1 do
  begin
    // 1. Сохраняем текущий зашифрованный блок, он станет маской для следующего шага
    Move(Buffer[i * 8], CurrentBlock, 8);

    // 2. Стандартная дешифрация блока Blowfish (8 байт)
    // Здесь должна быть твоя функция дешифрации блока
    Blowfish_DecryptBlock(@Buffer[i * 8]);

    // 3. Выполняем XOR дешифрованного блока с предыдущим зашифрованным
    for j := 0 to 7 do
    begin
      Buffer[i * 8 + j] := Buffer[i * 8 + j] xor PrevBlock[j];
    end;

    // 4. Запоминаем текущий зашифрованный блок как PrevBlock для следующей итерации
    Move(CurrentBlock, PrevBlock, 8);
  end;
end;












end.

