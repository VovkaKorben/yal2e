unit  laClasses;

interface

uses
    Classes, SysUtils, Generics.Collections, IdTCPClient, IdGlobal;

type


    TL2Object = class
    end;

    TL2Spawn = class (TL2Object)
    end;

    TL2Live = class (TL2Spawn)
    end;

    TL2Char = class (TL2Live)
    end;

    TL2User = class (TL2Char)
    public
        X, Y, Z: Integer;
        HP: integer;
    end;

    TEngine = class ; // Опережающее объявление

    // Легковесная структура для последовательного чтения данных из пакета (Advanced Record)
    TPacketReader = record
    private
        FData: TBytes;
        FOffset: integer;
    public
        constructor Create(const AData: TBytes; AStartOffset: integer = 1);
        function GetC: byte;     // 1 байт
        function GetH: word;     // 2 байта
        function GetD: integer;  // 4 байта
        function GetS: string;   // UTF-16LE строка
    end;

    // Легковесная структура для сборки пакетов
    TPacketBuilder = record
    private
        FData: TBytes;
    public
        procedure WriteC(Value: byte);
        procedure WriteH(Value: word);
        procedure WriteD(Value: integer);
        procedure WriteS(const Value: string);
        function GetPacket: TBytes;
    end;

    // Индивидуальный поток для блокирующего чтения сети для конкретного бота
    TEngineThread = class (TThread)
    private
        FEngine: TEngine;
    protected
        procedure Execute; override;
    public
        constructor Create(AEngine: TEngine);
    end;

    // Главный рабочий класс одного персонажа (инстанс бота)
    TEngine = class
    private
        FUser: TL2User;
        FEnv: TObjectDictionary<Cardinal, TL2Object>; // Хранилище окружения
        FThread: TEngineThread;
        FSocket: TIdTCPClient;
    public
        constructor Create;
        destructor Destroy; override;

        procedure Connect(const Host: string; Port: Word);
        procedure SendPacket(const Data: TBytes);

        // В будущем тут могут быть методы типа Connect(), MoveTo(), UseSkill() и т.д.

        property User: TL2User read FUser;
        property Env: TObjectDictionary<Cardinal, TL2Object> read FEnv;
    end;

    // Сигнатура глобальной процедуры-обработчика (без of object)
    TPacketHandler = procedure(engine: TEngine; var reader: TPacketReader);

implementation

{ TPacketReader }

constructor TPacketReader.Create(const AData: TBytes; AStartOffset: integer = 1);
begin
    // Сохраняем ссылку на массив. AStartOffset = 1, чтобы пропустить ID пакета
    FData := AData;
    FOffset := AStartOffset;
end;

function TPacketReader.GetC: byte;
begin
    Result := FData [FOffset];
    Inc(FOffset, 1);
end;

function TPacketReader.GetH: word;
begin
    Result := PWord(@FData [FOffset])^;
    Inc(FOffset, 2);
end;

function TPacketReader.GetD: integer;
begin
    Result := PInteger(@FData [FOffset])^;
    Inc(FOffset, 4);
end;

function TPacketReader.GetS: string;
var
    StartOff, StrLen: integer;
begin
    StartOff := FOffset;

    // Ищем конец строки: два нулевых байта подряд (#0#0)
    while FOffset + 1 < Length(FData) do
    begin
        if (FData [FOffset] = 0) and (FData [FOffset + 1] = 0) then
            Break;
        Inc(FOffset, 2);
    end;

    // Вычисляем длину строки в символах (каждый символ 2 байта)
    StrLen := (FOffset - StartOff) div 2;
    SetLength(Result, StrLen);

    if StrLen > 0 then
        Move(FData [StartOff], Result [1], StrLen * 2);

    Inc(FOffset, 2); // Пропускаем нули-терминаторы
end;

{ TPacketBuilder }

procedure TPacketBuilder.WriteC(Value: byte);
begin
    FData := FData + [Value];
end;

procedure TPacketBuilder.WriteH(Value: word);
begin
    FData := FData + TBytes(BitConverter.GetBytes(Value)); // Потребуется System.SysUtils
end;

procedure TPacketBuilder.WriteD(Value: integer);
begin
    FData := FData + TBytes(BitConverter.GetBytes(Value));
end;

procedure TPacketBuilder.WriteS(const Value: string);
begin
    if Value <> '' then
        FData := FData + TEncoding.Unicode.GetBytes(Value);
    FData := FData + [0, 0]; // Null-terminator (UTF-16)
end;

function TPacketBuilder.GetPacket: TBytes;
begin
    Result := FData;
end;

{ Обработчики пакетов }

procedure scKeyInit(engine: TEngine; var reader: TPacketReader);
begin
end;

procedure scMoveToLocation(engine: TEngine; var reader: TPacketReader);
//var    TargetX, TargetY, TargetZ: Integer;
begin
    engine.User.X := Reader.GetD;
    engine.User.Y := Reader.GetD;
    engine.User.Z := Reader.GetD;
    // engine.User.X := TargetX; // Обновляем состояние нашего движка
end;

// Таблица обработчиков (Lookup Table)
const
    PacketHandlers: array[0..255] of TPacketHandler = (
        scKeyInit,        // 0x00
        scMoveToLocation, // 0x01
        nil               // и так далее... нужно заполнить все 256 элементов
        );

{ TEngineThread }
constructor TEngineThread.Create(AEngine: TEngine);
begin
    FEngine := AEngine;
    inherited Create(false);
    FreeOnTerminate := false;
end;

procedure TEngineThread.Execute;
var
    PacketBytes: TBytes;
    Reader: TPacketReader;
    PacketLen: Word;
begin
    while not Terminated do
    begin
        try
            // Если мы еще не подключились, просто ждем
            if not FEngine.FSocket.Connected then
            begin
                Sleep(10);
                Continue;
            end;

            // Блокирующее чтение заголовка (2 байта длины) и затем тела
            PacketLen := FEngine.FSocket.IOHandler.ReadUInt16;
            FEngine.FSocket.IOHandler.ReadBytes(TIdBytes(PacketBytes), PacketLen - 2, False);
            
            if Length(PacketBytes) > 0 then
            begin
                Reader := TPacketReader.Create(PacketBytes);
                PacketHandlers[PacketBytes[0]](FEngine, Reader);
            end;
        except
            on E: Exception do
                Break;
        end;
    end;
end;

{ TEngine }

constructor TEngine.Create;
begin
    FEnv := TObjectDictionary<Cardinal, TL2Object>.Create([doOwnsValues]);
    FUser := TL2User.Create;
    FSocket := TIdTCPClient.Create(nil);
    FThread := TEngineThread.Create(Self);
end;

destructor TEngine.Destroy;
begin
    // Отключаем сокет перед убийством потока, чтобы сбросить блокировку Read
    if FSocket.Connected then
        FSocket.Disconnect;
        
    FThread.Terminate;
    FThread.WaitFor;
    FThread.Free;
    FSocket.Free;
    FEnv.Free;
    FUser.Free;
    inherited;
end;

procedure TEngine.Connect(const Host: string; Port: Word);
begin
    FSocket.Host := Host;
    FSocket.Port := Port;
    FSocket.Connect;
end;

procedure TEngine.SendPacket(const Data: TBytes);
var
    Len: Word;
    Buf: TBytes;
begin
    if not FSocket.Connected then Exit;
    Len := Length(Data) + 2;
    SetLength(Buf, Len);
    PWord(@Buf[0])^ := Len; // Пишем размер пакета в начало
    Move(Data[0], Buf[2], Length(Data)); // Копируем само тело пакета
    FSocket.IOHandler.Write(TIdBytes(Buf));
end;

end.