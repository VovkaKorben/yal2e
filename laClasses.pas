{ packets naming
ac - Auth Server -> Client 
ca - reverse
gc - Game Server -> Client
cg- reverse


}


unit  laClasses;

{$mode delphi}

interface

uses
    Classes, SysUtils, Generics.Collections, Types, SyncObjs,
    L2Socket; // Подключаем наш новый модуль

type
    esState = (esOffline, esAuth, esGame);

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
        X, Y, Z: integer;
        HP: integer;
    end;

    TEngine = class ; // Опережающее объявление


      // Индивидуальный поток для блокирующего чтения сети для конкретного бота
    TReceiveThread = class (TThread)
    private
        FEngine: TEngine;
    protected
        procedure Execute; override;
    public
        constructor Create(AEngine: TEngine);
    end;

    // Индивидуальный поток для блокирующей отправки пакетов
    TSendThread = class (TThread)
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
        FEnv:  TObjectDictionary<cardinal, TL2Object>; // Хранилище окружения
        FThread: TReceiveThread;
        FSendThread: TSendThread;
        FSocket: TL2Socket; // Заменяем TIdTCPClient на наш класс
        FSendQueue: TThreadedQueue<TBytes>;

    protected

        FState: esState;
    public
        constructor Create;
        destructor Destroy; override;

        procedure Connect(const Host: string; Port: word);
        procedure SendPacket(const Data: TBytes);

        // В будущем тут могут быть методы типа Connect(), MoveTo(), UseSkill() и т.д.

        property User: TL2User read FUser;
        property Env: TObjectDictionary<cardinal, TL2Object> read FEnv;
    end;


implementation

// Добавляем, чтобы были видны AuthHandler и (в будущем) GameHandler
uses authPackets;

{ Обработчики пакетов }


{ TReceiveThread }
constructor TReceiveThread.Create(AEngine: TEngine);
begin
    FEngine := AEngine;
    inherited Create(false);
    FreeOnTerminate := false;
end;

procedure TReceiveThread.Execute;
var
    data: TBytes;
    lenBytes: TBytes;
    dataLen: Word;
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

            // Блокирующее чтение заголовка (2 байта длины)
            if not FEngine.FSocket.ReceiveAll(lenBytes, 2) then Break;
            dataLen := PWord(@lenBytes[0])^;

            // Читаем тело пакета
            if not FEngine.FSocket.ReceiveAll(data, dataLen - 2) then Break;


            case FEngine.FState of
                esAuth: AuthHandler(FEngine, data);
                esGame: GameHandler(FEngine, data);

            end;


        except
            on E: Exception do
                Break;
        end;
    end;
end;

{ TSendThread }
constructor TSendThread.Create(AEngine: TEngine);
begin
    FEngine := AEngine;
    inherited Create(false);
    FreeOnTerminate := false;
end;

procedure TSendThread.Execute;
var
    Buf: TBytes;
begin
    while not Terminated do
    begin
        if not FEngine.FSocket.Connected then
        begin
            Sleep(10);
            Continue;
        end;

        // Пытаемся извлечь пакет. Таймаут 100мс позволяет циклу пойти дальше 
        // и проверить условие Terminated, если очередь пуста.
        if FEngine.FSendQueue.PopItem(Buf) = wrSignaled then
        begin
            try
                // В будущем сюда можно вставить фильтр пакетов:
                // if not ShouldSendPacket(Buf) then Continue;
                
                FEngine.FSocket.Send(Buf);
            except
                on E: Exception do
                    Break;
            end;
        end;
    end;
end;

{ TEngine }

constructor TEngine.Create;
begin
    FState := esOffline;
    FEnv := TObjectDictionary<cardinal, TL2Object>.Create([doOwnsValues]);
    FUser := TL2User.Create;
    FSocket := TL2Socket.Create; // Создаем экземпляр нашего класса
    
    // Создаем очередь на 1024 пакета. INFINITE - бесконечное ожидание записи (если забита), 
    // 100 - таймаут 100 мс на извлечение
    FSendQueue := TThreadedQueue<TBytes>.Create(1024, INFINITE, 100);
    
    FThread := TReceiveThread.Create(Self);
    FSendThread := TSendThread.Create(Self);
end;

destructor TEngine.Destroy;
begin
    // Отключаем сокет перед убийством потока, чтобы сбросить блокировку Read
    if FSocket.Connected then
        FSocket.Disconnect;

    FThread.Terminate;
    FSendThread.Terminate;
    
    // Разблокируем очередь, если поток завис на PopItem / PushItem
    FSendQueue.DoShutDown;

    FThread.WaitFor;
    FSendThread.WaitFor;
    FThread.Free;
    FSendThread.Free;
    FSendQueue.Free;
    FSocket.Free;
    FEnv.Free;
    FUser.Free;
    inherited;
end;

procedure TEngine.Connect(const Host: string; Port: word);
begin
    FSocket.Connect(Host, Port);
end;

procedure TEngine.SendPacket(const Data: TBytes);
var
    Len: word;
    Buf: TBytes;
begin
    if not FSocket.Connected then
        Exit;
        
    Len := Length(Data) + 2;
    SetLength(Buf, Len);
    PWord(@Buf [0])^ := Len; // Пишем размер пакета в начало
    Move(Data [0], Buf [2], Length(Data)); // Копируем само тело пакета
    
    // Вместо прямой отправки, просто складываем подготовленный массив в очередь
    FSendQueue.PushItem(Buf);
end;

end.