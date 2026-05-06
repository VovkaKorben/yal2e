
unit L2PacketBase;

interface

uses
    System.Classes, System.SysUtils, Blowfish;

type
    TL2PacketStream = class(TMemoryStream)
    private
        BFData: TBlowfishData;
        procedure EncryptPacket();

    public
        function ReadC: uint8;

        procedure WriteC(Value: uint8);
        procedure WriteH(Value: uint16);
        procedure WriteD(Value: int32);
        procedure WriteF(Value: Double);
        procedure WriteS(Value: string);

        // Подсчет контрольной суммы по алгоритму из статьи
        procedure AddChecksum;

        // Финализация: запись длины в первые 2 байта
        procedure PrepareToSend;
        procedure Init();
        procedure Fin();
        constructor Create(blowfishInitKey: string);

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

procedure TL2PacketStream.WriteD(Value: int32);
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
        Buffer := TEncoding.Unicode.GetBytes(Value);
        Write(Buffer[0], Length(Buffer));
    end;
    // null terminated
    WriteH(0);

end;

procedure TL2PacketStream.AddChecksum;
var
    xorResult: uint32;

    Ptr: PLongWord;
    checksumPos, i: int32;
    zero: uint8;
begin
    zero := 0;

    // pad to 8 bytes
    // checksumPos := (self.Size +5) and not 7;
    checksumPos := ((Self.Size - 2 + 7) and not 7) + 2;
    while (self.Size < checksumPos) do
        Write(zero, 1);

    // put checksum placeholder + four pad zeroes
    for I := 7 downto 0 do
        Write(zero, 1);

    xorResult := 0;
    Ptr := PLongWord(PByte(Self.Memory) + 2);
    for I := 0 to ((checksumPos - 2) div 4) - 1 do
    begin
        xorResult := xorResult xor Ptr^;
        Inc(Ptr);
    end;

    // write checksum
    Self.Position := checksumPos;
    Write(xorResult, 4);
end;

procedure TL2PacketStream.PrepareToSend;
var
    FullSize: uint16;
begin
    FullSize := Self.Size;
    Self.Position := 0;
    Write(FullSize, 2);

end;

function TL2PacketStream.ReadC: uint8;
begin
    Read(result, 1);
end;

procedure TL2PacketStream.Init();
begin
    self.Clear();
    // reserve 2 byte for packet size
    WriteH(0);
end;

procedure TL2PacketStream.Fin();
begin
    AddChecksum(); // calc xor checksum
    EncryptPacket(); // do blowfish
    PrepareToSend(); // add packet size
end;

constructor TL2PacketStream.Create(blowfishInitKey: string);
begin
    BlowfishInit(BFData, PChar(blowfishInitKey), Length(blowfishInitKey), nil);
end;

procedure TL2PacketStream.EncryptPacket();
var
    i: Integer;
    BlocksCount: Integer;
    Ptr: PByte;
begin
    BlocksCount := (self.Size - 2) div 8; // Определяем количество 8-байтовых блоков в теле пакета
    Ptr := PByte(self.Memory) + 2; // Указатель на начало данных (пропускаем заголовок 2 байта)
    for i := 0 to BlocksCount - 1 do
    begin
        BlowfishEncryptECB(BFData, Ptr, Ptr); // Шифруем блок на месте (InData и OutData указывают на один адрес)
        Inc(Ptr, 8); // Сдвигаем указатель на следующий блок (8 байт)
    end;
end;

end.

