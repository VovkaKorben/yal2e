unit packetUtils;
interface
 
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
        property Raw:TBytes read FData; 
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
 procedure  swap8(var data: tbytes);

    implementation
function swapEndianness(const v:uint32):uint32;inline;
begin
    result :=//
     ((v and $FF000000) shr 24) or //
    ((v and $00FF0000) shr 8) or //
    ((v and $0000FF00) shl 8) or //
    ((v and $000000FF) shl 24) ;
end;

procedure  swap8(var data: tbytes);
var i:int32;
    p:puint32;
begin
    p := PUint32(data);
    for i:=0 to (length(data) shr 2)-1 do
    begin
        p^ := swapEndianness(p^);
        inc(p);
    end;
end;

    { TPacketReader }
var INTERLUDE_PROTOCOL_BLOB,LEGACY_STATIC_BLOWFISH_KEY,STATIC_BLOWFISH_KEY:TBytes;

function CompareBytes(const a:TBytes;const b:TBytes):boolean;
begin
result:=  (Length(A) = Length(B)) and CompareMem(@A[0], @B[0], Length(A)) ;

end;
procedure LoadFromRes(resName:string;out data:TBytes):TBytes;
begin
// check res exists 
// else raise Exception.CreateFmt('Resource %s not found', [resName]);
//// set length
// load resource

end;



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

initialization
LoadFromRes('INTERLUDE_PROTOCOL_BLOB',INTERLUDE_PROTOCOL_BLOB);


end.