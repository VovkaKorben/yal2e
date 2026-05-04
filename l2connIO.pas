unit l2connIO;

interface

uses SysUtils, Classes, MyFiles, MyMath, Winapi.WinSock2;

procedure HexDump(stream: TMemoryStream);
function FileRead(const FileName: string; Stream: TMemoryStream): Boolean;
function SockRead(Stream: TMemoryStream): Boolean;
procedure DataWrite(const FileName: string; Stream: TMemoryStream);

implementation

const
    L2CAT_IP = '51.83.130.113';
    L2CAT_LOGIN_PORT = 2106;

procedure HexDump(stream: TMemoryStream);
var
    //    ceiledSize,
    ptr, rowCounter, rowLimit: int32;
    collectHex, collectAscii, ch: string;
    data: Pbyte;
begin
    if (not assigned(stream)) then
        Exit;
    Writeln(StringOfChar('-', 75));

    //    ceiledSize := (stream.Size + 15) and not 15;
    data := stream.Memory;
    ptr := 0;
    while ptr < stream.Size do
    begin
        rowCounter := 0;
        collectHex := format('%.04x  ', [ptr]);
        collectAscii := '';
        rowLimit := mymin(16, stream.Size - ptr);
        while rowCounter < rowLimit do
        begin
            collectHex := collectHex + IntToHex(data^, 2);
            collectHex := collectHex + ' ';
            if rowCounter = 7 then
                collectHex := collectHex + '| ';

            if (data^ in [32..127]) then
                ch := chr(data^)
            else
                ch := '.';
            collectAscii := collectAscii + ch;

            inc(rowCounter);
            inc(ptr);
            inc(data);
        end;
        if (rowCounter > 0) then
        begin
            Writeln(format('%-32s | %s', [collectHex, collectAscii]));
        end;

    end;

    //    Writeln(Format('%08x  %-23s  %-23s   %s %s', [i * 16, HexL, HexR, AscL, AscR]));

    Writeln(StringOfChar('-', 75));
end;

// --- recv_all(sock, n) ---

function RecvAll(Sock: TSocket; Buffer: Pointer; Len: Integer): Integer;
var
    Total, Received: Integer;
begin
    Total := 0;
    while Total < Len do
    begin
        Received := recv(Sock, PAnsiChar(NativeInt(Buffer) + Total)^, Len - Total, 0);
        if Received <= 0 then
            Break;
        Inc(Total, Received);
    end;
    Result := Total;
end;

// --- file_read(filename) ---

function FileRead(const FileName: string; Stream: TMemoryStream): Boolean;
begin
    Result := False;
    if FileExists(FileName) then
        try
            Stream.LoadFromFile(FileName);
            Result := True;
        except
            on E: Exception do
                Writeln('Ошибка при обработке: ', E.Message);
        end
    else
        Writeln('Файл ', FileName, ' не найден.');
end;

// --- data_write(filename, data) ---

procedure DataWrite(const FileName: string; Stream: TMemoryStream);
begin
    try
        Stream.SaveToFile(FileName);
        Writeln('Данные успешно сохранены в ', FileName);
    except
        on E: Exception do
            Writeln('Ошибка при работе с файлом: ', E.Message);
    end;
end;

// --- sock_read() ---

function SockRead(Stream: TMemoryStream): Boolean;
var
    WSA: TWSAData;
    Sock: TSocket;
    Addr: TSockAddrIn;
    Header: Word;
    PacketSize: Integer;
    //    Buf: array of Byte;
    aStr: AnsiString;
begin
    Result := False;
    if WSAStartup($0202, WSA) <> 0 then
        Exit;
    Sock := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    try
        Addr.sin_family := AF_INET;
        Addr.sin_port := htons(L2CAT_LOGIN_PORT);

        aStr := AnsiString(L2CAT_IP);

        Addr.sin_addr.S_addr := inet_addr(PAnsiChar(aStr));

        if connect(Sock, tsockaddr(addr), SizeOf(Addr)) <> SOCKET_ERROR then
        begin
            Writeln('Успешное подключение к ', L2CAT_IP);
            if RecvAll(Sock, @Header, 2) = 2 then
            begin
                PacketSize := Header - 2;
                Writeln('Ожидаемый размер данных: ', PacketSize, ' байт');
                Stream.SetSize(PacketSize);
                if RecvAll(Sock, Stream.Memory, PacketSize) = PacketSize then
                begin
                    Writeln('Данные получены успешно.');
                    Result := True;
                end
                else
                    Writeln('Ошибка: соединение разорвано при чтении тела.');
            end
            else
                Writeln('Ошибка: соединение разорвано при чтении заголовка.');
        end
        else
            Writeln('Ошибка: Сервер отклонил подключение.');
    finally
        closesocket(Sock);
        WSACleanup;
    end;
end;
end.

