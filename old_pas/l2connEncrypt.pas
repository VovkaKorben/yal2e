unit l2connEncrypt;

interface
uses
    System.Classes, System.SysUtils, Blowfish;
procedure DecryptLoginInit(Stream: TMemoryStream);

implementation

type
    DWORD = uint32;
    PDWORD = ^uint32;




    

const
  // Статический Blowfish ключ для Interlude (ровно 16 байт с завершающим нулем)
  // Взят напрямую из LoginServer.cs твоего проекта
  L2_INIT_BF_KEY: array[0..15] of Byte = (
    $5F, $40, $4D, $35, $56, $34, $56, $39,
    $56, $38, $56, $31, $56, $30, $5F, $00
  );

// Дешифратор блока Blowfish с правильным для L2 порядком байт (Little Endian)
procedure L2_BF_DecryptBlock(const Data: TBlowfishData; InData, OutData: Pointer);
var
  xL, xR, temp: DWORD;
  i: Integer;
begin
  // Читаем Little-Endian DWORDs напрямую, игнорируя ByteSwap из Blowfish.pas
  xL := PDWORD(InData)^;
  xR := PDWORD(Pointer(NativeInt(InData) + 4))^;

  // Стандартный цикл дешифрации Blowfish (16 раундов назад)
  for i := 17 downto 2 do
  begin
    xL := xL xor Data.PBoxM[i];
    xR := xR xor (((Data.SBoxM[0, (xL shr 24) and $FF] + Data.SBoxM[1, (xL shr 16) and $FF])
          xor Data.SBoxM[2, (xL shr 8) and $FF]) + Data.SBoxM[3, xL and $FF]);
    temp := xL; xL := xR; xR := temp;
  end;

  // Финальные XOR-ы из P-Box
  xL := xL xor Data.PBoxM[1];
  xR := xR xor Data.PBoxM[0];

  // Записываем результат: xR в младшие байты, xL в старшие (согласно Blowfish.cs в l2net)
  PDWORD(OutData)^ := xR;
  PDWORD(Pointer(NativeInt(OutData) + 4))^ := xL;
end;

// XOR дешифрация (строго по NewCrypt.cs)
procedure L2_NewCrypt_DecXor(Data: PByte; Size: Integer; Key: Integer);
var
  Pos, Stop: Integer;
  Edx, Ecx: Integer;
begin
  Stop := 8;         // Первые 8 байт НЕ ксорятся
  Pos := Size - 8;   // Начинаем с 8-го байта с конца
  Ecx := Key;        // Для Init пакета Key всегда 0

  while (Pos >= Stop) do
  begin
    Edx := PInteger(@Data[Pos])^;
    Edx := Edx xor Ecx;
    Ecx := Ecx - Edx;
    PInteger(@Data[Pos])^ := Edx;
    Dec(Pos, 4);
  end;
end;

procedure DecryptLoginInit(Stream: TMemoryStream);
var
  BFData: TBlowfishData;
  DataPtr: PByte;
  Size, i: Integer;
begin
  if (Stream = nil) or (Stream.Size < 16) then Exit;

  DataPtr := Stream.Memory;
  Size := Stream.Size;

  // ЭТАП 1: XOR (выполняется ПЕРЕД Blowfish, ключ 0)
  L2_NewCrypt_DecXor(DataPtr, Size, 0);

  // ЭТАП 2: Blowfish
  // Инициализируем стандартно (P-box XOR-ится ключом)
  BlowfishInit(BFData, @L2_INIT_BF_KEY[0], 16, nil);

  // Поблочная дешифрация с правильным порядком байт (in-place)
  for i := 0 to (Size div 8) - 1 do
  begin
    L2_BF_DecryptBlock(BFData, @DataPtr[i * 8], @DataPtr[i * 8]);
  end;

  Stream.Position := 0;
end;

end.

