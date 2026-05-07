unit L2Socket;

{$mode delphi}

interface

uses
  // Используем условную компиляцию для поддержки Delphi и Free Pascal
  {$IFDEF FPC}
  sockets,
  {$ELSE}
  WinSock,
  {$ENDIF}
  SysUtils, Classes;

type
  TL2Socket = class(TObject)
  private
    FSocket: TSocket;
    FConnected: Boolean;
    function GetConnected: Boolean;
  public
    constructor Create;
    destructor Destroy; override;

    function Connect(const AHost: string; APort: Word): Boolean;
    procedure Disconnect;

    function Send(const ABuffer: TBytes): Integer;
    function ReceiveAll(var ABuffer: TBytes; ALength: Integer): Boolean;

    property Connected: Boolean read GetConnected;
  end;

implementation


  {$IFNDEF FPC}
  // Для Delphi под Windows нужен модуль Windows для MakeWord
 uses Windows;
  {$ELSE}
  {$ENDIF}

{ TL2Socket }

constructor TL2Socket.Create;
begin
  inherited Create;
  FSocket := INVALID_SOCKET;
  FConnected := False;

  // Инициализация WinSock для Delphi (в FPC это делается автоматически в модуле sockets)
  {$IFNDEF FPC}
  var
    WSAData: TWSAData;
  begin
    WSAStartup(MakeWord(2, 2), WSAData);
  end;
  {$ENDIF}
end;

destructor TL2Socket.Destroy;
begin
  Disconnect;
  {$IFNDEF FPC}
  WSACleanup;
  {$ENDIF}
  inherited Destroy;
end;

function TL2Socket.GetConnected: Boolean;
begin
  Result := FConnected;
end;

function TL2Socket.Connect(const AHost: string; APort: Word): Boolean;
var
  HostEnt: PHostEnt;
  {$IFDEF FPC}
  SockAddr: TInetSockAddr;
  {$ELSE}
  SockAddr: TSockAddrIn;
  {$ENDIF}
begin
  Result := False;
  if FConnected then
    Disconnect;

  FSocket := socket(AF_INET, SOCK_STREAM, 0);
  if FSocket = INVALID_SOCKET then
    Exit;

  HostEnt := gethostbyname(PChar(AHost));
  if HostEnt = nil then
  begin
    closesocket(FSocket);
    FSocket := INVALID_SOCKET;
    Exit;
  end;

  {$IFDEF FPC}
  FillChar(SockAddr, SizeOf(SockAddr), 0);
  SockAddr.sin_family := AF_INET;
  SockAddr.sin_port := htons(APort);
  SockAddr.sin_addr.s_addr := PLongWord(HostEnt^.h_addr_list^)^;
  Result := sockets.connect(FSocket, @SockAddr, SizeOf(SockAddr)) = 0;
  {$ELSE}
  SockAddr.sin_family := AF_INET;
  SockAddr.sin_port := htons(APort);
  SockAddr.sin_addr.s_addr := PLongWord(HostEnt^.h_addr_list^)^;
  Result := WinSock.connect(FSocket, SockAddr, SizeOf(SockAddr)) = 0;
  {$ENDIF}

  FConnected := Result;
  if not FConnected then
  begin
    closesocket(FSocket);
    FSocket := INVALID_SOCKET;
  end;
end;

procedure TL2Socket.Disconnect;
begin
  if FSocket <> INVALID_SOCKET then
  begin
    shutdown(FSocket, SD_BOTH);
    closesocket(FSocket);
  end;
  FSocket := INVALID_SOCKET;
  FConnected := False;
end;

function TL2Socket.Send(const ABuffer: TBytes): Integer;
begin
  Result := -1;
  if not FConnected then Exit;
  Result := sockets.send(FSocket, ABuffer[0], Length(ABuffer), 0);
end;

function TL2Socket.ReceiveAll(var ABuffer: TBytes; ALength: Integer): Boolean;
var
  BytesRead, TotalBytesRead: Integer;
begin
  Result := False;
  if not FConnected or (ALength <= 0) then Exit;

  SetLength(ABuffer, ALength);
  TotalBytesRead := 0;

  while TotalBytesRead < ALength do
  begin
    BytesRead := sockets.recv(FSocket, ABuffer[TotalBytesRead], ALength - TotalBytesRead, 0);

    if BytesRead <= 0 then
    begin
      Disconnect; // Соединение разорвано или произошла ошибка
      SetLength(ABuffer, 0);
      Exit;
    end;

    Inc(TotalBytesRead, BytesRead);
  end;

  Result := True;
end;

end.