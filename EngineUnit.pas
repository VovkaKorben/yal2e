
unit EngineUnit;

interface

uses sysutils, classes, L2PacketBase, LoginPackets;

type 
    AccountState =   (asNone, asLogged);
    // TOnPacketEvent =   procedure (Sender: TObject; APacket: TL2PacketStream) of object;

    TEngine =   class;



        TSocketThread =   class(TThread)
            private 
                FEngine:   TEngine;
                procedure Execute;
                override;
            public 
                constructor Create(AEngine: TEngine);
        end;

        TEngine =   class
            private 
                FLogin,FPassword:   string;
                BFData:   TBlowfishData;
                FSocket:   TSocket;
                FAddr:   TSockAddrIn;
                FThread:   TSocketThread;
                FSessionID:   uint32;

                sendPacket:   TL2PacketStream;

                FOnPacket:   TOnPacketEvent;


                // Внутренние методы обработки
                procedure ProcessIncomingPacket(APacket: TL2PacketStream);
                procedure HandleInit(APacket: TL2PacketStream);


                // procedure PacketDispatcher(APacket: TL2PacketStream);
                procedure FInitBlowfish(key:string);
            public 

                state:   AccountState;

                property OnPacket:   TOnPacketEvent read FOnPacket write FOnPacket;

                function login(login, pass: string):   boolean;
                function PacketToHex():   string;
                constructor Create(login,password:string);
                destructor Destroy;
                override;

        end;

        implementation

        const blowfishKey =   '[;''.]94-31==-&%@!^+]';


            constructor TSocketThread.Create(AEngine: TEngine);
        begin
            inherited Create(False);
            FEngine := AEngine;
            FreeOnTerminate := True;
        end;

        procedure TSocketThread.Execute;
        var 
            Header:   Word;
            Res:   Integer;
            Packet:   TL2PacketStream;
        begin
            Packet := TL2PacketStream.Create;
            try
                while not Terminated do
                    begin
                        // 1. Читаем заголовок (2 байта)
                        Res := recv(FEngine.FSocket, Header, 2, 0);
                        if (Res <= 0) or Terminated then Break;

                        // 2. Читаем тело (Header - 2 байта)
                        Packet.Clear;
                        Packet.SetSize(Header);
                        Packet.Position := 0;
                        Packet.Write(Header, 2);

                        Res := recv(FEngine.FSocket, PByte(Packet.Memory)^ + 2, Header - 2, 0);
                        if (Res > 0) and not Terminated then
                            begin
                                Packet.Position := 2;

    // Передаем пакет на обработку в логику движка (в этом же потоке!)
                                FEngine.ProcessIncomingPacket(Packet);
                            end
                        else Break;
                    end;
            finally
                Packet.Free;
                FEngine.State := asError;
                TThread.Synchronize(nil, FEngine.SyncStatus);
        end;
    end;

{ TEngine }

    constructor TEngine.Create(login, password: string);
var 
    WSAData:   TWSAData;
begin
    inherited;
    FLogin := login;
    FPassword := password;


    BlowfishInit(BFData, PChar(blowfishKey), Length(blowfishKey), nil);


    WSAStartup($0202, WSAData);
    // Инициализация сокетов
    sendPacket := TL2PacketStream.Create;
    FSocket := INVALID_SOCKET;
    state := asNone;

end;

destructor TEngine.Destroy;
begin
    Disconnect;
    WSACleanup;
    sendPacket.Free;
    inherited;
end;

function TEngine.login():   boolean;
begin
    RequestAuthLogin(sendPacket, login, pass);


end;
function TEngine.Connect(IP: string; Port: Word):   Boolean;
begin
    Result := False;
    FSocket := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if FSocket = INVALID_SOCKET then Exit;

    FAddr.sin_family := AF_INET;
    FAddr.sin_port := htons(Port);
    FAddr.sin_addr.S_addr := inet_addr(PAnsiChar(AnsiString(IP)));

    if Winapi.Winsock2.connect(FSocket, FAddr, SizeOf(FAddr)) <> SOCKET_ERROR then
        begin
            state := asConnected;
            // Сразу после коннекта ждем Init пакет от сервера
            Result := ReceivePacket(sendPacket);
        end;
end;
function TEngine.PacketToHex():   string;
var 
    i:   Integer;
    P:   PByte;
begin
    Result := '';
    if (sendPacket = nil) or (sendPacket.Size = 0) then
        Exit;

    P := sendPacket.Memory;
    for i := 0 to sendPacket.Size - 1 do
        begin


















// пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅ пїЅ Hex пїЅ пїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅ
            Result := Result + IntToHex(P^, 2) + ' ';
            Inc(P);
        end;
    Result := Trim(Result);


















// пїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅ пїЅ пїЅпїЅпїЅпїЅпїЅ
end;

procedure TEngine.ProcessIncomingPacket(APacket: TL2PacketStream);
var 
    Opcode:   Byte;
begin

    // Тут можно воткнуть дешифратор Blowfish, если пакет пришел от Login
    // EncryptPacket(BFData); 

    Opcode := APacket.ReadC;

    case Opcode of 
        $00:   HandleInit(APacket);
        $03:
               begin
                   State := asLogged;
                   TThread.Synchronize(nil, SyncStatus);
                   // Вот тут синкаем, радость-то какая!
               end;
        $01:
               begin
                   State := asError;
                   LastError := 'Login Failed';
                   TThread.Synchronize(nil, SyncStatus);
               end;
    end;
end;



end.
