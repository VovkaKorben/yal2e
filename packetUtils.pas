unit packetUtils;{$mode delphi}

interface

uses
    SysUtils;

    // Легковесная структура для последовательного чтения данных из пакета (Advanced Record)
type

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
        function Copy(APos, ALength: integer): TBytes; // Копирование N байт в новый массив
        property Raw: TBytes read FData;
    end;

  // Легковесная структура для сборки пакетов
    TPacketBuilder = record
    private
        FData: TBytes;
        FOffset: int32;
    public
        constructor Create(bufferSize: int32);
        procedure Write8(Value: uint8); inline;
        procedure Write16(Value: uint16); inline;
        procedure Write32(Value: uint32); inline;
        procedure WriteS(const Value: string); inline;

        procedure Fill( fillCount: int32;fillValue: uint8); inline;
        procedure Pad(count: int32; fill_value: uint8 = 0); inline;
        procedure PadToSize(padSize: int32; fill_value: uint8 = 0);
        procedure Reset();
        procedure Finalize();
        property Offset: int32 read FOffset;
    end;

procedure swap8(var data: tbytes);


function LoadFromRes(const resName: string): TBytes;

implementation
// --------------------------------------------------------------------- TPacketBuilder
// ----------------------------------------------------- 
// --------------------------------------

procedure TPacketBuilder.Finalize(const packetType:uint32);
begin
// вырезает [0..FOffset-1] из исходного буфера и кладёт в очередь с флагом packetType

end;

procedure TPacketBuilder.Reset();
begin
    FOffset := 0;
end;

constructor TPacketBuilder.Create(const bufferSize: int32);
begin
    SetLength(FData, bufferSize);
end;

procedure TPacketBuilder.Write8(const value: uint8);
begin
    FData[FOffset] := value;
    inc(offset);
end;

procedure TPacketBuilder.Write16(const value: uint16);
begin
    PUint16(@FData [FOffset])^ := Value;
    inc(offset, 2);
end;

procedure TPacketBuilder.Write32(const value: uint32);
begin
    PUint32(@bytes [FOffset])^ := Value;
    inc(offset, 4);
end;

procedure TPacketBuilder.PadToSize(padSize: int32; fill_value: uint8 = 0);
var
    Padding: int32;
begin
    Padding := (padSize - (FOffset and (padSize - 1))) and (padSize - 1);
    if Padding > 0 then
    begin
        FillChar(FData [foffset], Padding, fill_value);
        inc(foffset, Padding);
    end;
end;

procedure TPacketBuilder.WriteS(const Value: string);
var
    L: integer;
    UniStr: UnicodeString;
begin
    UniStr := UnicodeString(Value);
    L := Length(FData);
    SetLength(FData, L + Length(UniStr) * 2 + 2);
    if Length(UniStr) > 0 then
        Move(UniStr [1], FData [L], Length(UniStr) * 2);
    FData[Length(FData) - 2] := 0;
    FData[Length(FData) - 1] := 0;
end;

procedure TPacketBuilder.Fill( fillCount: int32;fillValue: uint8); inline;
begin
    if fillCount > 0 then
    begin
        FillChar(FData [FOffset], fillCount, fillValue);
        inc(foffset, fillCount);
    end;
end;


function swapEndianness(const v: uint32): uint32; inline;
begin
    result :=//
        ((v and $FF000000) shr 24) or //
        ((v and $00FF0000) shr 8) or //
        ((v and $0000FF00) shl 8) or //
        ((v and $000000FF) shl 24);
end;

procedure swap8(var data: tbytes);
var
    i: int32;
    p: puint32;
begin
    p := PUint32(data);
    for i := 0 to (length(data) shr 2) - 1 do
    begin
        p^ := swapEndianness(p^);
        inc(p);
    end;
end;

    { TPacketReader }
var
    INTERLUDE_PROTOCOL_BLOB, LEGACY_STATIC_BLOWFISH_KEY, STATIC_BLOWFISH_KEY: TBytes;

function CompareBytes(const a: TBytes; const b: TBytes): boolean;
begin
    result := (Length(A) = Length(B)) and CompareMem(@A [0], @B [0], Length(A));

end;

function LoadFromRes(const resName: string): TBytes;
begin
// Инициализируем возвращаемое значение (самый правильный способ убрать Warning)
    Result := nil;
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
    UniStr: UnicodeString;
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
    SetLength(UniStr, StrLen);

    if StrLen > 0 then
        Move(FData [StartOff], UniStr [1], StrLen * 2);

    Result := string(UniStr);

    Inc(FOffset, 2); // Пропускаем нули-терминаторы
end;

function TPacketReader.Copy(APos, ALength: integer): TBytes;
begin
    // Copy безопасно отрабатывает выход за границы массива
    Result := Copy(FData, APos, ALength);
    //Inc(FOffset, Length(Result)); // Сдвигаем смещение ровно на столько байт, сколько удалось скопировать
end;


initialization
    INTERLUDE_PROTOCOL_BLOB := LoadFromRes('INTERLUDE_PROTOCOL_BLOB');


end.