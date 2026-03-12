unit L2PacketBase;

interface

uses
    System.Classes, System.SysUtils, Winapi.Winsock2;

type
    TL2PacketStream = class(TMemoryStream)
    public
        // Запись базовых типов L2
        procedure WriteC(Value: Byte); // 1 байт (char)
        procedure WriteH(Value: Word); // 2 байта (short)
        procedure WriteD(Value: Integer); // 4 байта (int)
        procedure WriteF(Value: Double); // 8 байт (double)
        procedure WriteS(Value: string); // UTF-16LE строка с нулевым терминатором

        // Подсчет контрольной суммы по алгоритму из статьи
        procedure AddChecksum;

        // Финализация: запись длины в первые 2 байта
        procedure PrepareToSend;
    end;

implementation

{ TL2PacketStream }

procedure TL2PacketStream.WriteC(Value: Byte);
begin
    Write(Value, 1);
end;

procedure TL2PacketStream.WriteH(Value: Word);
begin
    Write(Value, 2);
end;

procedure TL2PacketStream.WriteD(Value: Integer);
begin
    Write(Value, 4);
end;

procedure TL2PacketStream.WriteF(Value: Double);
begin
    Write(Value, 8);
end;

procedure TL2PacketStream.WriteS(Value: string);
var
    Buffer: TBytes;
begin
    if Value <> '' then
    begin
        // В L2 строки передаются в Unicode (UTF-16LE)
        Buffer := TEncoding.Unicode.GetBytes(Value);
        Write(Buffer[0], Length(Buffer));
    end;
    // Конец строки: два нулевых байта [cite: 140]
    WriteH(0);
end;

procedure TL2PacketStream.AddChecksum;
var
    Chk: LongWord;
    Temp: LongWord;
    I: Integer;
    Ptr: PLongWord;
    DataSize: Integer;
begin
    // Алгоритм из статьи: XOR 32-битных слов [cite: 60, 61, 68]
    Chk := 0;
    DataSize := Self.Size - 2; // Не считаем первые 2 байта длины [cite: 59]

    // Резервируем место под чексумму (4 байта), если еще не сделали
    if Self.Position < Self.Size then
        Self.Size := Self.Size + 4;

    Ptr := PLongWord(PByte(Self.Memory) + 2);
    // Итерируемся по 4 байта [cite: 67]
    for I := 0 to (DataSize div 4) - 2 do
    begin
        Chk := Chk xor Ptr^;
        Inc(Ptr);
    end;

    // Записываем результат в конец пакета [cite: 69]
    Self.Position := Self.Size - 4;
    Write(Chk, 4);
end;

procedure TL2PacketStream.PrepareToSend;
var
    FullSize: Word;
begin
    FullSize := Self.Size;
    Self.Position := 0;
    Write(FullSize, 2); // Записываем общую длину пакета [cite: 52]
end;

end.

