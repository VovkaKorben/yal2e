unit EngineUnit;

interface

uses sysutils, classes, L2PacketBase, LoginPackets;
type
    AccountState = (asNone, asLogged);
    TEngine = class
        state: AccountState;
        sendPacket: TL2PacketStream;
    public
        function login(login, pass: string): boolean;
        function PacketToHex(): string;
        constructor Create;
        destructor Destroy; override;

    end;

implementation

{ TEngine }

constructor TEngine.Create;
begin
    sendPacket := TL2PacketStream.Create;
end;

destructor TEngine.Destroy;
begin
    sendPacket.Free;
    inherited;
end;

function TEngine.login(login, pass: string): boolean;
begin
  
    RequestAuthLogin(sendPacket, login, pass);
  
    
end;

function TEngine.PacketToHex(): string;
var
    i: Integer;
    P: PByte;
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
    Result := Trim(Result); // пїЅпїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅ пїЅпїЅпїЅпїЅпїЅпїЅ пїЅ пїЅпїЅпїЅпїЅпїЅ
end;
end.

