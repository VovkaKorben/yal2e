unit EngineUnit;

interface

uses L2PacketBase, LoginPackets;
type
    AccountState = (asNone, asLogged);
    TEngine = class
        state: AccountState;
        sendPacket: TL2PacketStream;
    public
        function login(login, pass: string): boolean;
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
    sendPacket.Clear;
    RequestAuthLogin(sendPacket, login, pass);
    sendPacket.AddChecksum;
    sendPacket.PrepareToSend;
end;

end.

